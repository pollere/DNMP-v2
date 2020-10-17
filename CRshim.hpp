#ifndef CRSHIM_HPP
#define CRSHIM_HPP
/*
 * CRshim.hpp: Command-Reply DNMP shim
 *
 * Copyright (c) 2019,  Pollere Inc.
 *
 * This file is part of the Distributed Network Measurement Protocol (DNMP)
 * proof-of-concept (PoC), a project primarily funded under NIST 70NANB18H186.
 * See AUTHORS.md for complete list of syncps authors and contributors.
 *
 * DNMP is free software: you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 *
 * DNMP is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this source, e.g., COPYING.md file. If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * CRshim provides an API between DNMP and the syncps protocol. It is both
 * DNMP and syncps aware.  A client app (usually) creates one CRshim.
 * A nod should create one CRshim for each topic to which it subscribes,
 * e.g., nod/local, nod/all and nod/id.
 *
 * This file contains the methods implementing the DNMP command/reply shim.
 * It is a self-contained, 'header-only' library.
 */

#include <utility>
#include "syncps/syncps.hpp"

using namespace syncps;
using namespace ndn;

/**
 * @brief Name-based accessors for Reply name components.
 *
 * These use the schema string table to map a component's name to
 * its index in that publication.
 */
struct RName : public Name {
    using Name::Name;

    const ndn::Name::Component& operator[](std::string_view s) const
    {
        return get(m_n2i.at(s));
    }
    std::string str(std::string_view s) const
    {
        auto c = get(m_n2i.at(s));
        return std::string((const char*)c.getValue().buf(), c.getValue().size());
    }
  private:
    // XXX temporary placeholder component name to index map. Will be
    // replaced by schema-based version for release.
    static inline const std::unordered_map<std::string_view, int8_t> m_n2i {
        { "root", 0 },
        { "domain", 1 },
        { "tType", 2 },
        { "tId", 3 },
        { "topic", 4 },
        { "Id", 5 },
        { "pType", 6 },
        { "pArgs", 7 },
        { "origin", 8 },
        { "cTS", 9 },
        { "rSrcId", 10 },
        { "rTS", 11 },
    };
};
struct Reply : public Publication {
    using Publication::Publication;

    const RName& name() const { return (const RName&)(Publication::getName()); }

    template <typename T>
    const ndn::Name::Component& operator[](T t) const { return name()[t]; }

    /*
     * return the time difference (in seconds) between timepoint 'tp'
     * and the timepoint in component 'idx' this pub's name
     */
    template <typename T>
    double timeDelta(T t, std::chrono::system_clock::time_point tp =
                          std::chrono::system_clock::now()) const
    {
        return std::chrono::duration_cast<std::chrono::duration<double>>
                (tp - name()[t].toTimestamp()).count();
    }

    /*
     * return the time difference (in seconds) between 
     * the timepoints in components 'l' and 'f' this pub's name
     */
    template <typename T>
    double timeDelta(T l, T f) const
    {
        return std::chrono::duration_cast<std::chrono::duration<double>>
                (name()[l].toTimestamp() - name()[f].toTimestamp()).count();
    }
};

class CRshim;

using rpHndlr = std::function<void(const Reply&, CRshim&)>;
using cmHndlr = std::function<void(RName&&, CRshim&)>;
using Timer = ndn::scheduler::ScopedEventId;
using TimerCb = std::function<void()>;

#define LOG(x)

class CRshim
{
  public:
    CRshim(ThreadsafeFace& face, const std::string& target) :
        m_face(face), m_sync(m_face, targetToPrefix(target), isExpired, filterPubs),
        m_topic{topicName(target)}
    {}
    CRshim(const std::string& target) :
        CRshim(*makeFace(), target) {}
    CRshim(const CRshim& s1, const std::string& target) :
        CRshim(s1.m_face, target) {}

    void run()
    {
        if (!m_work)
            // mwork keeps the ioService running.
            m_work = std::make_shared<boost::asio::io_service::work>(m_face.getIoService());
        m_face.getIoService().run();
    }
    auto prefix() const { return m_topic; }
    ThreadsafeFace& face() const { return m_face; }

    /* command/reply client methods */

    /*
     * build a command for the probeType (passed in as a string)
     * with the optional probeArgs (passed in as a string)
     * Creates an NDN name according to DNMP spec for command
    */
    Publication buildCmd(const std::string& s, const std::string& a = "")
    {
        Name cmd(prefix());
        cmd.append(Name::Component(s)).append(Name::Component(a))
           .append(myPID())
           .appendTimestamp(std::chrono::system_clock::now());
        return Publication(cmd);
    }

    /*
     * subscribe to a topic for the expected reply, then publish the command
    */
    CRshim& issueCmd(const std::string& ptype, const std::string& pargs,
        const rpHndlr& rh)
    { 
        auto cmd(buildCmd(ptype, pargs));
        m_sync.subscribeTo(expectedReply(cmd), 
            [this,rh](auto r){ rh((const Reply&)(r),*this); });
        m_sync.publish(std::move(cmd));
        return *this;
    }

    void doCommand(const std::string& ptype, const std::string& pargs, const rpHndlr& rh)
    {
        issueCmd(ptype, pargs, rh);
        run();
    }

    /* command/reply NOD methods */

    /*
     * Subscribe to command topic and wait for an incoming publication
     */
    CRshim& waitForCmd(const cmHndlr& ch)
    {
        m_sync.subscribeTo(prefix().getSubName(0, prefix().size() - 3),
                           [this, ch](auto c) { ch(expectedReply(c), *this); });
        return *this;
    }

    void sendReply(Name& n, std::string&& rv)
    {
        // append nod id & timestamp to reply name then publish reply
        n.append(Name::Component(myPID())).appendTimestamp(std::chrono::system_clock::now());
        Publication r(n);
        m_sync.publish(std::move(r.setContent((const uint8_t*)(rv.data()), rv.size())));
    }

    /*
     * Create an array of shims (all using the same face) from an
     * argument list of target names.
     */
    template <typename ... T>
    static auto shims(T...target) {
        ThreadsafeFace& f = *makeFace();
        return std::array<std::shared_ptr<CRshim>,sizeof...(T)> {std::make_shared<CRshim>(f, target)...};
    }

    /* Common methods */

    /*
     * Construct the 'reply' topic Name expected for a particular 'command'.
     * Used for both NODs and Clients so doesn't add replySrcID or timestamp
     */
    RName expectedReply(const Publication& pub)
    {
        size_t n = prefix().size() - 4;
        const auto& cmd = pub.getName();
        RName r;
        r.append(cmd.getPrefix(n)).append("reply").append(cmd.getSubName(n + 1));
        return r;
    }

    static std::string myPID()
    {
        return addHostname("_", "pid" + std::to_string(getpid()));
    }

    Timer schedule(std::chrono::nanoseconds d, const TimerCb& cb) {
        return m_sync.schedule(d, cb);
    }
  protected:
    static inline const FilterPubsCb filterPubs =
        [](auto& pOurs, auto& pOthers) mutable {
            // Only reply if at least one of the pubs is ours. Order the
            // reply by ours/others then most recent first (to minimize latency).
            // Respond with as many pubs will fit in one Data.
            if (pOurs.empty()) {
                return pOurs;
            }
            const auto cmp = [](const auto p1, const auto p2) {
                return p1->getName()[-1].toTimestamp() >
                       p2->getName()[-1].toTimestamp();
            };
            if (pOurs.size() > 1) {
                std::sort(pOurs.begin(), pOurs.end(), cmp);
            }
            std::sort(pOthers.begin(), pOthers.end(), cmp);
            for (auto& p : pOthers) {
                pOurs.push_back(p);
            }
            return pOurs;
        };
    static inline const IsExpiredCb isExpired = [](auto p) {
        auto dt = std::chrono::system_clock::now() - p.getName()[-1].toTimestamp();
        return dt >= maxPubLifetime+maxClockSkew || dt <= -maxClockSkew;
    };
    // -- temporary pre-schemaLib place holders --
    // these will be replaced with trust schema library routines
    // in the next version.
    /*
     * Construct the NDN name prefix to use for syncps communication
     * with application-level target 't'. In the POC this is a fixed
     * mapping with 'local' mapping to "/localhost/dnmp" and anything
     * else mapping to "/localnet/dnmp/<t>"
     * (In the trust-schema-based shim, this mapping is described
     * in a site-specific trust schema.)
     */
    static std::string targetToPrefix(const std::string& t)
    {
        return t == "local"? "/localhost/dnmp" : "localnet/dnmp/" + t;
    }
    static std::string addHostname(const char* sep, std::string id)
    {
        id += sep;
        char h[256];
        if (gethostname(h, sizeof(h) - 1) == 0) {
            h[sizeof(h) - 1] = 0;
            id += h;
        } else {
            id += "??";
        }
        return id;
    }
    static std::string myID()
    {
        return "uid" + std::to_string(getuid());
    }
    /*
     * construct the full topic name prefix for this session  given
     * the application-level target 'target'. For the POC this name
     * has a fixed format. (In the trust-schema-based shim, it is
     * determined by a validator/constructor schema.)
     */
    static std::string topicName(const std::string& target)
    {
        std::string p("myHouse/dnmp/nod/");
        p += target;
        p += "/command/";
        p += myID();
        return p;
    }
    // -- end of place holders --
  private:
    static ThreadsafeFace*
    makeFace()
    {
      ThreadsafeFace* face = new ThreadsafeFace();
      // Use the system default key chain and certificate name to sign commands.
      KeyChain* keyChain = new KeyChain();
      face->setCommandSigningInfo(*keyChain, keyChain->getDefaultCertificateName());
      return face;
    }

    ThreadsafeFace& m_face;
    std::shared_ptr<boost::asio::io_service::work> m_work;
    SyncPubsub m_sync;
    Name m_topic;     // full name of the topic
};

#endif // CRSHIM_CPP
#define SYNCPS_SYNCPS_HPP
