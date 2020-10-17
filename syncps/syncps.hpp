/*
 * Copyright (c) 2019,  Pollere Inc.
 *
 * This file is part of syncps (NDN sync for pubsub).
 * See AUTHORS.md for complete list of syncps authors and contributors.
 *
 * syncps is free software: you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 *
 * syncps is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * syncps, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 **/

#ifndef SYNCPS_SYNCPS_HPP
#define SYNCPS_SYNCPS_HPP

#include <cstring>
#include <functional>
#include <limits>
#include <map>
#include <random>
#include <unordered_map>

#include <ndn-ind/threadsafe-face.hpp>
#include <ndn-ind/security/key-chain.hpp>
#include <ndn-ind/security/validator-null.hpp>
#include <ndn-ind/util/logging.hpp>
#include <ndn-ind/lite/util/crypto-lite.hpp>
#include <ndn-ind/util/scheduler.hpp>
#include <ndn-ind/encoding/protobuf-tlv.hpp>

#include "iblt.hpp"
// This include is produced in the Makefile by:
// protoc --cpp_out=. syncps-content.proto
#include "syncps-content.pb.h"

namespace syncps
{
INIT_LOGGER("syncps.SyncPubsub");

using Name = ndn::Name;         // type of a name
using Publication = ndn::Data;  // type of a publication
using SigningInfo = ndn::SigningInfo; // how to sign publication
using ScopedEventId = ndn::scheduler::ScopedEventId; // scheduler events

namespace tlv
{
    enum { syncpsContent = 129 }; // tlv for block of publications
} // namespace tlv

constexpr int maxPubSize = 1300;    // max payload in Data (approximate)

constexpr std::chrono::milliseconds maxPubLifetime = std::chrono::seconds(1);
constexpr std::chrono::milliseconds maxClockSkew = std::chrono::seconds(1);

/**
 * @brief app callback when new publications arrive
 */
using UpdateCb = std::function<void(const Publication&)>;
/**
 * @brief app callback when publication is seen on another node's list
 */
using PublishCb = std::function<void(const Publication&, bool)>;
/**
 * @brief app callback to test if publication is expired
 */
using IsExpiredCb = std::function<bool(const Publication&)>;
/**
 * @brief app callback to filter peer publication requests
 */
using PubPtr = std::shared_ptr<const Publication>;
using VPubPtr = std::vector<PubPtr>;
using FilterPubsCb = std::function<VPubPtr(VPubPtr&,VPubPtr&)>;

/**
 * @brief sync a lifetime-bounded set of publications among
 *        an arbitrary set of nodes.
 *
 * Application should call 'publish' to add a new publication to the
 * set and register an UpdateCallback that is called whenever new
 * publications from others are received. Publications are automatically
 * deleted (without notice) at the end their lifetime.
 *
 * Publications are named, signed objects (ndn::Data). The last component of
 * their name is a version number (local ms clock) that is used to bound the
 * pub lifetime. This component is added by 'publish' before the publication
 * is signed so it is protected against replay attacks. App publications
 * are signed by pubCertificate and external publications are verified by
 * pubValidator on arrival. (XXX not yet)
 */

class SyncPubsub
{
  public:
    class Error : public std::runtime_error
    {
      public:
        using std::runtime_error::runtime_error;
    };
    /**
     * @brief constructor
     *
     * Registers syncPrefix in NFD and sends a sync interest
     *
     * @param face application's face
     * @param syncPrefix The ndn name prefix for sync interest/data
     * @param syncInterestLifetime lifetime of the sync interest
     * @param expectedNumEntries expected entries in IBF
     */
    SyncPubsub(ndn::ThreadsafeFace& face, Name syncPrefix,
        IsExpiredCb isExpired, FilterPubsCb filterPubs,
        std::chrono::milliseconds syncInterestLifetime = std::chrono::seconds(4),
        size_t expectedNumEntries = 85)  // = 128/1.5 (see detail/iblt.hpp)
        : m_face(face),
          m_syncPrefix(std::move(syncPrefix)),
          m_expectedNumEntries(expectedNumEntries),
          m_validator(m_validatorNull), //XXX
          m_scheduler(m_face.getIoService()),
          m_iblt(expectedNumEntries),
          m_pcbiblt(expectedNumEntries),
          m_signingInfo(ndn::SigningInfo(ndn::SigningInfo::SIGNER_TYPE_SHA256)),
          m_isExpired{std::move(isExpired)}, m_filterPubs{std::move(filterPubs)},
          m_syncInterestLifetime(syncInterestLifetime),
          m_registeredPrefix(m_face.registerPrefix(
              m_syncPrefix,
              [this](auto& prefix, auto& i, auto& face, auto id, auto& filter) { onSyncInterest(*prefix, *i); },
              [this](auto& n) { onRegisterFailed(*n); },
              [this](auto&/*n*/, auto/*id*/) { m_registering = false; sendSyncInterest(); }))
    { }

    /**
     * @brief handle a new publication from app
     *
     * A publication is published at most once and
     * lives for at most pubLifetime.
     *
     * @param pub the object to publish
     */
    uint32_t publish(Publication&& pub)
    {
        m_keyChain.sign(pub, m_signingInfo); //XXX
        if (isKnown(pub)) {
            _LOG_WARN("republish of '" << pub.getName() << "' ignored");
        } else {
            _LOG_INFO("Publish: " << pub.getName());
            ++m_publications;
            addToActive(std::move(pub), true);
            // new pub may let us respond to pending interest(s).
            if (! m_delivering) {
                sendSyncInterest();
                handleInterests();
            }
        }
        return hashPub(pub);
    }
    /**
     * @brief handle a new publication from app
     *
     * A publication is published at most once and
     * lives for at most pubLifetime. This version
     * takes a callback so publication can be confirmed
     * or failure reported so "at least once" or other
     * semantics can be built into shim. Sets callback.
     *
     * @param pub the object to publish
     */
    uint32_t  publish(Publication&& pub, PublishCb&& cb)
    {
        auto h = publish(std::move(pub));
        //using returned hash of signed pub
        m_pubCbs[h] = std::move(cb);
        m_pcbiblt.insert(h);
        return h;
    }

    /**
     * @brief subscribe to a subtopic
     *
     * Calls 'cb' on each new publication to 'topic' arriving
     * from some external source.
     *
     * @param  topic the topic
     */
    SyncPubsub& subscribeTo(const Name& topic, UpdateCb&& cb)
    {
        // add to subscription dispatch table. NOTE that an existing
        // subscription to 'topic' will be changed to the new callback.
        m_subscription[topic] = std::move(cb);
        _LOG_INFO("subscribeTo: " << topic);
        return *this;
    }

    /**
     * @brief unsubscribe to a subtopic
     *
     * A subscription to 'topic', if any, is removed.
     *
     * @param  topic the topic
     */
    SyncPubsub& unsubscribe(const Name& topic)
    {
        m_subscription.erase(topic);
        _LOG_INFO("unsubscribe: " << topic);
        return *this;
    }

    /**
     * @brief set Sync Interest lifetime
     *
     * @param t interest lifetime in ms
     */
    SyncPubsub& setSyncInterestLifetime(std::chrono::milliseconds t)
    {
        m_syncInterestLifetime = t;
        return *this;
    }

    /**
     * @brief schedule a callback after some time
     *
     * This lives here to avoid exposing applications to the complicated mess
     * of NDN's relationship to Boost
     *
     * @param after how long to wait (in nanoseconds)
     * @param cb routine to call
     */
    ScopedEventId schedule(std::chrono::nanoseconds after,
                           const std::function<void()>& cb)
    {
        return m_scheduler.schedule(after, cb);
    }

    /**
     * @brief set publication signingInfo
     *
     * All publications are signed when published using this signing info.
     * If no signing info is supplied, a SHA256 signature is used
     * (essentially a high quality checksum without provenance or
     * trust semantics).
     *
     * @param si a valid ndn::Security::SigningInfo 
     */
    SyncPubsub& setSigningInfo(const SigningInfo& si)
    {
        m_signingInfo = si;
        return *this;
    }

    /**
     * @brief set packet validator
     *
     * All arriving Data and/or Interest packets are validated
     * with this validator. If no validator is set, an 'accept
     * all' validator is used.
     *
     * @param validator new packet validator to use
     * XXX can't do this because validator base class is not copyable
    SyncPubsub& setValidator(ndn::security::v2::Validator& validator)
    {
        m_validator = validator;
        return *this;
    }
     */

    const ndn::Validator& getValidator() { return m_validator; }

    /**
     * Get the publication from the active set by exact name match.
     * @param name The name of the publication to search for.
     * @return A shared_ptr to the publication, or a null shared_ptr if not found.
     */
    std::shared_ptr<const Publication> getPubByName(const Name& name)
    {
      for (auto p = m_active.begin(); p != m_active.end(); ++p) {
        if (p->first->getName() == name)
          return p->first;
      }
      return std::shared_ptr<const Publication>();
    }

   private:

    /**
     * @brief reexpress our current sync interest so it doesn't time out
     */
    void reExpressSyncInterest()
    {
        // The interest is sent 20ms ahead of when it's due to time out
        // to allow for propagation and precessing delays.
        //
        // note: previously scheduled timer is automatically cancelled.
        auto when = m_syncInterestLifetime - std::chrono::milliseconds(20);
        m_scheduledSyncInterestId =
            m_scheduler.schedule(when, [this] { sendSyncInterest(); });
    }

    /**
     * @brief Send a sync interest describing our publication set
     *        to our peers.
     *
     * Creates & sends interest of the form: /<sync-prefix>/<own-IBF>
     */
    void sendSyncInterest()
    {
        // if an interest is sent before the initial register is done the reply can't
        // reach us. don't send now since the register callback will do it.
        if (m_registering) {
            return;
        }
        // schedule the next send
        reExpressSyncInterest();

        // Build and ship the interest. Format is
        // /<sync-prefix>/<ourLatestIBF>
        ndn::Name name = m_syncPrefix;
        m_iblt.appendToName(name);

        ndn::Interest syncInterest(name);
        uint8_t nonceBytes[4];
        ndn::CryptoLite::generateRandomBytes(nonceBytes, 4);
        m_currentInterest = ndn::Blob(nonceBytes, 4);
        syncInterest.setNonce(m_currentInterest)
            .setCanBePrefix(true)
            .setMustBeFresh(true)
            .setInterestLifetime(m_syncInterestLifetime);
        m_face.expressInterest(syncInterest,
                [this](auto& i, auto& d) {
                    m_validator.validate(*d,
                        [this, i](auto& d) { onValidData(*i, d); },
                        [](auto& d, auto& e) { _LOG_INFO("Invalid: " << e << " Data " << d); }); },
                [](auto& i) { _LOG_INFO("Timeout for " << i->toUri()); },
                [](auto& i, auto&/*n*/) { _LOG_INFO("Nack for " << i->toUri()); });
        ++m_interestsSent;
        // For logging, interpret the nonce as a hex integer.
        _LOG_DEBUG("sendSyncInterest " << std::hex
                      << *((uint32_t*)m_currentInterest.buf()) << "/" << hashIBLT(name) << std::dec);
    }

    /**
     * @brief Send a sync interest sometime soon
     */
    void sendSyncInterestSoon()
    {
        _LOG_DEBUG("sendSyncInterestSoon");
        m_scheduledSyncInterestId =
            m_scheduler.schedule(std::chrono::milliseconds(3), [this]{ sendSyncInterest(); });
    }

    /**
     * @brief callback to Process a new sync interest from NFD
     *
     * Get differences between our IBF and IBF in the sync interest.
     * If we have some things that the other side does not have,
     * reply with a Data packet containing (some of) those things.
     *
     * @param prefixName prefix registration that matched interest
     * @param interest   interest packet
     */
    void onSyncInterest(const ndn::Name& prefixName, const ndn::Interest& interest)
    {
        if (interest.getNonce().equals(m_currentInterest)) {
            // library looped back our interest
            return;
        }
        const ndn::Name& name = interest.getName();
        // For logging, interpret the nonce as a hex integer.
        _LOG_DEBUG("onSyncInterest " << std::hex << *((uint32_t*)interest.getNonce().buf()) << "/"
                      << hashIBLT(name) << std::dec);

        if (name.size() - prefixName.size() != 1) {
            _LOG_INFO("invalid sync interest: " << interest.toUri());
            return;
        }
        if (!  handleInterest(name)) {
            // couldn't handle interest immediately - remember it until
            // we satisfy it or it times out;
            m_interests[name] = std::chrono::system_clock::now() +
                                    m_syncInterestLifetime;
        }
    }

    void handleInterests()
    {
        _LOG_DEBUG("handleInterests");
        auto now = std::chrono::system_clock::now();
        for (auto i = m_interests.begin(); i != m_interests.end(); ) {
            const auto& [name, expires] = *i;
            if (expires <= now || handleInterest(name)) {
                i = m_interests.erase(i);
            } else {
                ++i;
            }
        }
    }

    bool handleInterest(const ndn::Name& name)
    {
        // 'Peeling' the difference between the peer's iblt & ours gives
        // two sets:
        //   have - (hashes of) items we have that they don't
        //   need - (hashes of) items we need that they have
        IBLT iblt(m_expectedNumEntries);
        try {
            iblt.initialize(name.get(-1));
        } catch (const std::exception& e) {
            _LOG_WARN(e.what());
            return true;
        }
        std::set<uint32_t> have;
        std::set<uint32_t> need;
        if(m_pubCbs.size()) {
            ((m_iblt - m_pcbiblt) - iblt).listEntries(have, need);
            for (const auto hash : need) {
            if (auto h = m_hash2pub.find(hash); h != m_hash2pub.end()) {
                // 2^0 bit of p->second is =0 if pub expired; 2^1 bit is 1 if we
                // did publication.
                if (const auto p = m_active.find(h->second); p != m_active.end()
                    && (p->second & 1U) != 0 && (p->second & 2U) != 0) {
                    if(m_pubCbs.count(hash)) {  //published here and has cb
                        m_pubCbs[hash]((*(h->second)), true);  //publication confirmed
                        m_pubCbs.erase(hash);
                        m_pcbiblt.erase(hash);
                    }
                }
            }

            }
            have.clear();
            need.clear();
        }
        (m_iblt - iblt).listEntries(have, need);
        _LOG_DEBUG("handleInterest " << std::hex << hashIBLT(name) << std::dec
                      << " need " << need.size() << ", have " << have.size());

        // If we have things the other side doesn't, send as many as
        // will fit in one Data. Make two lists of needed, active publications:
        // ones we published and ones published by others.

        VPubPtr pOurs, pOthers;
        for (const auto hash : have) {
            if (auto h = m_hash2pub.find(hash); h != m_hash2pub.end()) {
                // 2^0 bit of p->second is =0 if pub expired; 2^1 bit is 1 if we
                // did publication.
                if (const auto p = m_active.find(h->second); p != m_active.end()
                    && (p->second & 1U) != 0) {
                    ((p->second & 2U) != 0? &pOurs : &pOthers)->push_back(h->second);
                }
            }
        }
        pOurs = m_filterPubs(pOurs, pOthers);
        if (pOurs.empty()) {
            return false;
        }
        syncps_message::SyncpsContentMessage pubs;
        size_t pubsSize = 0;
        for (const auto& p : pOurs) {
            _LOG_DEBUG("Send pub " << p->getName());
            auto encoding = (*(p)).wireEncode();
            pubsSize += encoding.size();
            ndn::ProtobufTlv::addTlv(*pubs.mutable_syncps_content(), encoding);
            if (pubsSize >= maxPubSize) {
                break;
            }
        }
        sendSyncData(name, ndn::ProtobufTlv::encode(pubs));
        return true;
    }

    /**
     * @brief Send a sync data packet responding to a sync interest.
     *
     * Send a packet containing one or more publications that are known
     * to be in our active set but not in the interest sender's set.
     *
     * @param name  is the name from the sync interest we're responding to
     *              (data packet's base name)
     * @param pubs  is the list of publications (data packet's payload)
     */
    void sendSyncData(const ndn::Name& name, const ndn::Blob& pubs)
    {
        _LOG_DEBUG("sendSyncData: " << name);
        auto data = std::make_shared<ndn::Data>();
        data->setName(name).setContent(pubs);
        data->getMetaInfo().setFreshnessPeriod(maxPubLifetime / 2);
        m_keyChain.sign(*data, m_signingInfo);
        m_face.putData(*data);
    }

    /**
     * @brief Process sync data after successful validation
     *
     * Add each item in Data content that we don't have to
     * our list of active publications then notify the
     * application about the updates.
     *
     * @param interest interest for which we got the data
     * @param data     sync data content
     */
    void onValidData(const ndn::Interest& interest, const ndn::Data& data)
    {
        _LOG_DEBUG("onValidData: " << interest.getNonce().toHex() << "/"
                       << hashIBLT(interest.getName())
                       << " " << data.getName());

        syncps_message::SyncpsContentMessage pubs;
        try {
            ndn::ProtobufTlv::decode(pubs, data.getContent());
        } catch (std::runtime_error& ex) {
            _LOG_WARN("Ignoring sync Data with wrong content type or other error: " <<
                         ex.what());
            return;
        }

        // if publications result from handling this data we don't want to
        // respond to a peer's interest until we've handled all of them.
        m_delivering = true;
        auto initpubs = m_publications;

        for (auto i = 0; i < pubs.syncps_content().publications_size(); ++i) {
            ndn::Blob e;
            try {
                e = ndn::ProtobufTlv::getTlv(pubs.syncps_content(), "publications", i);
            } catch (std::runtime_error& ex) {
                _LOG_WARN("Ignoring sync Data with wrong Publication type or other error: " <<
                          ex.what());
                return;
            }
            //XXX validate pub against schema here
            Publication pub;
            pub.wireDecode(e);
            if (m_isExpired(pub) || isKnown(pub)) {
                _LOG_DEBUG("ignore expired or known " << pub.getName());
                continue;
            }
            // we don't already have this publication so deliver it
            // to the longest match subscription.
            // XXX lower_bound goes one too far when doing longest
            // prefix match. It would be faster to stick a marker on
            // the end of subscription entries so this wouldn't happen.
            // Also, it would be faster to do the comparison on the
            // wire-format names (excluding the leading length value)
            // rather than default of component-by-component.
            const auto& p = addToActive(std::move(pub));
            const auto& nm = p->getName();
            auto sub = m_subscription.lower_bound(nm);
            if ((sub != m_subscription.end() && sub->first.isPrefixOf(nm)) ||
                (sub != m_subscription.begin() && (--sub)->first.isPrefixOf(nm))) {
                _LOG_DEBUG("deliver " << nm << " to " << sub->first);
                sub->second(*p);
            } else {
                _LOG_DEBUG("no sub for  " << nm);
            }
        }

        // We've delivered all the publications in the Data.
        // If this is our currently active sync interest, send an
        // interest to replace the one consumed by the Data.
        // If deliveries resulted in new publications, try to satisfy
        // pending peer interests.
        m_delivering = false;
        if (interest.getNonce().equals(m_currentInterest)) {
            sendSyncInterest();
        }
        if (initpubs != m_publications) {
            handleInterests();
        }
    }

    /**
     * @brief Methods to manage the active publication set.
     */

    // publications are stored using a shared_ptr so we
    // get to them indirectly via their hash.

    uint32_t hashPub(const Publication& pub) const
    {
        const auto& b = pub.wireEncode();
        return ndn::CryptoLite::murmurHash3(N_HASHCHECK,
                           b.buf(), b.size());
    }

    bool isKnown(uint32_t h) const
    {
        //return m_hash2pub.contains(h);
        return m_hash2pub.find(h) != m_hash2pub.end();
    }

    bool isKnown(const Publication& pub) const
    {
        // publications are stored using a shared_ptr so we
        // get to them indirectly via their hash.
        return isKnown(hashPub(pub));
    }

    std::shared_ptr<Publication> addToActive(Publication&& pub, bool localPub = false)
    {
        _LOG_DEBUG("addToActive: " << pub.getName());
        auto hash = hashPub(pub);
        auto p = std::make_shared<Publication>(pub);
        m_active[p] = localPub? 3 : 1;
        m_hash2pub[hash] = p;
        m_iblt.insert(hash);

        // We remove an expired publication from our active set at twice its pub
        // lifetime (the extra time is to prevent replay attacks enabled by clock
        // skew).  An expired publication is never supplied in response to a sync
        // interest so this extra hold time prevents end-of-lifetime spurious
        // exchanges due to clock skew.
        //
        // Expired publications are kept in the iblt for at least the max clock skew
        // interval to prevent a peer with a late clock giving it back to us as soon
        // as we delete it.

        m_scheduler.schedule(maxPubLifetime, [this, p, hash] { m_active[p] &=~ 1U;
                                                if(m_pubCbs.count(hash)) {
                                                    m_pubCbs[hash]((*p), false);
                                                    m_pubCbs.erase(hash);
                                                    m_pcbiblt.erase(hash);
                                                } });
        m_scheduler.schedule(maxPubLifetime + maxClockSkew,
            [this, hash] { m_iblt.erase(hash); sendSyncInterestSoon(); });
        m_scheduler.schedule(maxPubLifetime * 2, [this, p] { removeFromActive(p); });

        return p;
    }

    void removeFromActive(const PubPtr& p)
    {
        _LOG_DEBUG("removeFromActive: " << (*p).getName());
        m_active.erase(p);
        m_hash2pub.erase(hashPub(*p));
    }

    /**
     * @brief Log a message if setting an interest filter fails
     *
     * @param prefix
     */
    void onRegisterFailed(const ndn::Name& prefix) const
    {
        _LOG_ERROR("onRegisterFailed " << prefix);
        BOOST_THROW_EXCEPTION(Error("onRegisterFailed " + prefix.toUri()));
    }

    uint32_t hashIBLT(const Name& n) const
    {
        const auto& b = n[-1].getValue();
        return ndn::CryptoLite::murmurHash3(N_HASHCHECK,
                           b.buf(), b.size());
    }

  private:
    ndn::ThreadsafeFace& m_face;
    ndn::Name m_syncPrefix;
    uint32_t m_expectedNumEntries;
    ndn::ValidatorNull m_validatorNull;
    ndn::Validator& m_validator;
    ndn::scheduler::Scheduler m_scheduler;
    std::map<const Name, std::chrono::system_clock::time_point> m_interests{};
    IBLT m_iblt;
    IBLT m_pcbiblt;
    ndn::KeyChain m_keyChain;
    SigningInfo m_signingInfo;
    // currently active published items
    std::unordered_map<std::shared_ptr<const Publication>, uint8_t> m_active{};
    std::unordered_map<uint32_t, std::shared_ptr<const Publication>> m_hash2pub{};
    std::map<const Name, UpdateCb> m_subscription{};
    std::unordered_map <uint32_t, PublishCb> m_pubCbs;
    IsExpiredCb m_isExpired;
    FilterPubsCb m_filterPubs;
    std::chrono::milliseconds m_syncInterestLifetime;
    ndn::scheduler::ScopedEventId m_scheduledSyncInterestId;
    //ndn::ScopedPendingInterestHandle m_interest;
    uint64_t m_registeredPrefix;
    ndn::Blob m_currentInterest;   // nonce of current sync interest
    uint32_t m_publications{};      // # local publications
    uint32_t m_interestsSent{};
    bool m_delivering{false};       // currently processing a Data
    bool m_registering{true};
};

}  // namespace syncps

#endif  // SYNCPS_SYNCPS_HPP
