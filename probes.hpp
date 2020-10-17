/*
 * probes.hpp: proof-of-concept DNMP probes
 *
 * Copyright (C) 2019 Pollere, Inc.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, see <https://www.gnu.org/licenses/>.
 *  You may contact Pollere, Inc at info@pollere.net.
 *
 *  The DNMP proof-of-concept is not intended as production code.
 *  More information on DNMP is available from info@pollere.net
 */

/*      Probes 
 *
 * Probes that can be used by a PoC DNMP NOD. Must follow format of accepting a string
 * that can be parsed for any required arguments and returning results in a string
 * that the DNMP syncer publisher will convert to Data.
 * Each probe has a DNMP probeType name and is added to the probeTable at the end
 * of this file. Each Probe needs to implement one of these functions and uses the
 * passed in callback to pass the response (as a string) back to the NOD. Probes
 * must check arguments to ensure makes sense.
 *
 * This version starts from the original DNMP release that runs with ndn-cxx and
 * has changes to work with the ndn-ind library. It makes use of code from the
 * examples folder under ndn-ind. That code has: 
 * Copyright (C) 2015-2020 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 *
 * Probe-specific functions that are called back when the SegmentFetcher::fetch
 * returns the status as a Blob and processes that status. These are set up in
 * statusQuery::send with a nod callback that takes the formatted string to 
 * create a reply.
 */

#include <iostream>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <functional>
#include <random>
#include <unordered_map>

using namespace std;
using namespace ndn;

/*
 * Passed to every Probe to use to return responses to NOD
 */
using nodRespCB = std::function<void(std::string)>;

/*
 * Pinger Probe only uses timestamps from Publication name, no status needed
 */

static void echoProbe(const std::string& args, Face&, nodRespCB cb) {
    if(!args.empty())
        LOG("echoProbe: nonempty argument is ignored");
    cb(std::string(""));
}

/*
 * Most Probes query status from Forwarder so must supply Probe-specific
 * call back functions to process the returned Blob into a string that is
 * sent to the NOD with the nodRespCB and perform any additional Probe work.
 */

#include <ndn-ind/util/logging.hpp>
using processStatusCB =
    std::function<void(const std::string&,const Blob&,nodRespCB&)>;

/*
 * Called by Probes that get the local NFD's status
 * Takes care of sending the Interest and gets the status Data.
 * Need probe-specific process functions that are called back when the Data is
 * received and these call the passed in callback.
 */

static void statusQuery(const std::string& args, ThreadsafeFace& face,
                        nodRespCB&& cb, processStatusCB scb, const char* iname)
{
  try {
    Interest interest{Name(iname)};
    interest.setInterestLifetimeMilliseconds(2000); // 2 seconds
    interest.setCanBePrefix(true);
    interest.setMustBeFresh(true);

    _LOG_INFO("statusQuery entity sending Interest:" << interest.toUri());

    face.expressInterest(interest,
	[a = args, cb = std::move(cb), scb](auto i, auto d)
    mutable { scb(a, d->getContent(), cb);},
	[](auto& i) { _LOG_INFO("Timeout for " << i->toUri()); },
	[](auto& i, auto&/*n*/) { _LOG_INFO("Nack for " << i->toUri()); });
  } catch (std::exception& e) {
      _LOG_INFO("Exception: ");
      _LOG_INFO(e.what());
  }
}

/*
 * The Forwarder Status Probe queries Forwarder for general status metrics.
 * The FSmetrics set may be used to select particular metrics rather than
 * returning all.
 */

static const std::set<std::string> FSmetrics = {
    "NfdVersion",
    "StartTimestamp",
    "CurrentTimestamp",
    "Uptime",
    "NameTreeEntries",
    "FibEntries",
    "PitEntries",
    "MeasurementsEntries",
    "CsEntries",
    "Interests",
    "Data",
    "Nacks",
    "SatisfiedInterests",
    "UnsatisfiedInterests",
    "all"
};

#include <ndn-ind/encoding/protobuf-tlv.hpp>
#include "formats/forwarder-status.pb.h"
#include <ctime>

static void
processFS(const std::string& a, const Blob& encodedMessage, nodRespCB cb) {
    LOG("processFS got args " + a); // a tells what to return: all or match a
    ndn_message::ForwarderStatusMessage fwStatus;
    ProtobufTlv::decode(fwStatus, encodedMessage);

    // Format message for reply to client
    std::stringstream result;
    result << "Forwarder Status ";
    result << "   (version=" << fwStatus.nfdversion() << ")" << endl;
    bool all = !a.compare("all");
    if(all || !a.compare("Uptime")) {
        auto uptm = (fwStatus.currenttimestamp() - fwStatus.starttimestamp())/1000.;
        int t = (int) uptm;
        result << "   Uptime: ";
        if(uptm > 86400) {
            result << t / 86400 << "D";
            t = t % 86400;
        }
        if(uptm > 3600) {
            result << ":" << t/3600 << "H";
            t = t % 3600;
        }
        if(uptm > 60) {
            result << ":" << t/60 << "M";
            t = t % 60;
        }
        if(t>0 || uptm < 60)
            result << ":" << t << "S";
        result << " (" << uptm << " seconds)" << endl;
    }
    if(all || !a.compare("StartTimestamp")) {
        result << "   StartTimestamp=" << toIsoString
          (fromMillisecondsSince1970(fwStatus.starttimestamp()), true) << endl;
    }
    if(all || !a.compare("CurrentTimestamp")) {
        result << "   CurrentTimestamp=" << toIsoString
          (fromMillisecondsSince1970(fwStatus.currenttimestamp()), true) << endl;
    }
    if(all || !a.compare("NameTreeEntries")) {
        result << "   NameTreeEntries=" << fwStatus.nnametreeentries() << endl;
    }
    if(all || !a.compare("FibEntries")) {
        result << "   FibEntries=" << fwStatus.nfibentries() << endl;
    }
    if(all || !a.compare("PitEntries")) {
        result << "   PitEntries=" << fwStatus.npitentries() << endl;
    }
    if(all || !a.compare("MeasurementsEntries")) {
        result << "   MeasurementsEntries=" << fwStatus.nmeasurementsentries() << endl;
    }
    if(all || !a.compare("CsEntries")) {
        result << "   CSEntries=" << fwStatus.ncsentries() << endl;
    }
    if(all || !a.compare("Interests")) {
        result << "   Interests: in=" << fwStatus.nininterests()
        << ", out=" << fwStatus.noutinterests() << endl;
    }
    if(all || !a.compare("Data")) {
        result << "   Data: in=" << fwStatus.nindata()
        << ", out=" << fwStatus.noutdata() << endl;
    }
    if(all || !a.compare("Nacks")) {
        result << "   Nacks: in=" << fwStatus.ninnacks()
        << ", out=" << fwStatus.noutnacks() << endl;
    }
    if(all || !a.compare("SatisfiedInterests")) {
        result << "   Satisfied   Interests=" << fwStatus.nsatisfiedinterests() << endl;
    }
    if(all || !a.compare("UnsatisfiedInterests")) {
        result << "   Unsatisfied Interests=" << fwStatus.nunsatisfiedinterests() << endl;
    }
    cb (result.str());
}

void FwdProbe(const std::string& args, ThreadsafeFace& face, nodRespCB&& cb) {
    //get the specific desired metric
    auto a = args.empty()? "all"s : args;
    LOG("nfdFwdProbe to get metric " + a);

    if(FSmetrics.find(a) == FSmetrics.end()) {
        LOG("no match for metric");
        cb(std::string("Forwarder Status probe has no entry for " + a));
    }
    try {
        statusQuery(a, face, std::move(cb), processFS, "/localhost/nfd/status/general");
    }
    catch (const std::exception& e) {
        LOG("Error: ");
        LOG(e.what());
    }
}

/*
 * FaceProbe gets the Face List
 * If argument is a face id, just returns entry for that face
 */

// This include is produced by: protoc --cpp_out=. face-status.proto
// proto and format from jefft test-list-faces example 
#include "formats/face-status.pb.h"

static void
processFL(const std::string& a, const Blob& encodedMessage, nodRespCB cb) {
    LOG("processFL got args " + a);
    bool all = !a.compare("all");
    int fid;
    if(!all) {
        try {
            fid = std::stoi (a);
        } catch (const std::exception& e) {
            LOG("Error: ");
            LOG(e.what());
            cb ("Probe could not convert argument to face id");
            return;
        }
    }

    ndn_message::FaceStatusMessage fsMessage;
    ProtobufTlv::decode(fsMessage, encodedMessage);

    std::stringstream result;
    result << "Forwarder Faces:" << endl;
    for (size_t iEntry = 0; iEntry < fsMessage.face_status_size(); ++iEntry) {
        const ndn_message::FaceStatusMessage_FaceStatus face =
         fsMessage.face_status(iEntry);
        if(!all && face.face_id() != fid) { continue; }

        result << "  faceid=" << face.face_id() <<
        " remote=" << face.uri() <<
        " local=" << face.local_uri();
        if (face.has_expiration_period())
        // Convert milliseconds to seconds.
        result << " expires=" <<
        ::round((double)face.expiration_period() / 1000) << "s";
        result << " counters={" << "in={" << face.n_in_interests() <<
        "i " << face.n_in_datas() << "d " << face.n_in_bytes() << "B}" <<
        " out={" << face.n_out_interests() << "i "<< face.n_out_datas() <<
        "d " << face.n_out_bytes() << "B}" << "}" <<
        " " << (face.face_scope() == 1 ? "local" : "non-local") <<
        " " << (face.face_persistency() == 2 ? "permanent" :
             face.face_persistency() == 1 ? "on-demand" : "persistent") <<
        " " << (face.link_type() == 1 ? "multi-access" : "point-to-point") <<
        endl;
    }

    cb (result.str());
}

void FaceProbe(const std::string& args, ThreadsafeFace& face, nodRespCB&& cb) {
    auto a = args.empty()? "all"s : args;
    LOG("FaceProbe with argument " + args);

    try {
        statusQuery(a, face, std::move(cb), processFL, "/localhost/nfd/faces/list");
    }
    catch (const std::exception& e) {
        LOG("Error: ");
        LOG(e.what());
    }
}

/*
 * RIBProbe gets the RIB List
 * If a prefix is passed in argument, only prints that entry
 */

// This include is produced by: protoc --cpp_out=. rib-entry.proto
// proto and format from jefft test-list-rib example
#include "formats/rib-entry.pb.h"

const static std::unordered_map<uint16_t, std::string> routeOrigin = {
    {0, "app"},
    {255, "static"},
    {128, "nlsr"},
    {129, "prefix announcement"},
    {65, "auto prefix propagation client"},
    {64, "nfd-autoreg tool endhost"},
    {66, "nfd-autoconfig remote router"}
};

static void
processRL(const std::string& a, const Blob& encodedMessage, nodRespCB cb) {
    LOG("processRL got args " + a);
    bool all = !a.compare("all");
    string prefix(a);

    ndn_message::RibEntryMessage ribMessage;
    ProtobufTlv::decode(ribMessage, encodedMessage);

    std::stringstream result;
    if(all) {
        result << "Forwarder RIB:" << endl;
    }
    for (int iEntry = 0; iEntry < ribMessage.rib_entry_size(); ++iEntry) {
        const ndn_message::RibEntryMessage_RibEntry& ribEntry = ribMessage.rib_entry(iEntry);
        if(!all && prefix.compare(ProtobufTlv::toName(ribEntry.name()).toUri()))
        {
            continue;
        }
        // get the prefix name
        result << "  Prefix: " << ProtobufTlv::toName(ribEntry.name()).toUri() << endl;
        // get routes
        for (int iRoute = 0; iRoute < ribEntry.routes_size(); ++iRoute) {
            const ndn_message::RibEntryMessage_Route& route = ribEntry.routes(iRoute);
            std::string origin;
            try {
                origin.assign(routeOrigin.at(route.origin()));
            } catch (const std::exception&) {
                origin.assign(to_string(route.origin()));
            }
            result << "  route={faceId=" << route.face_id() << " (origin=" <<
                origin << " cost=" << route.cost();
            if (route.flags() & 1)
                result << " ChildInherit";
            if (route.flags() & 2)
                result << " Capture";
            if (route.has_expiration_period())
                result << " expirationPeriod=" << route.expiration_period();
            result << ")}" << endl;
        }
    }
    cb (result.str());  //if prefix is set and no match found, string should be empty
}

void RIBProbe(const std::string& args, ThreadsafeFace& face, nodRespCB&& cb) {
    auto a = args.empty()? "all"s : args;
    LOG("RIBProbe with argument " + args);

    try {
        statusQuery(a, face, std::move(cb), processRL, "/localhost/nfd/rib/list");
    }
    catch (const std::exception& e) {
        LOG("Error: ");
        LOG(e.what());
    }
}

/*  Probe Table */

using probeFunc = std::function<void(const std::string&, ThreadsafeFace&, nodRespCB)>;

const static std::unordered_map<std::string, probeFunc> probeTable = {
/*
    {"Strategy"s, StrategyProbe},
    {"perFS"s, periodicProbe},
*/
    {"RIB"s, RIBProbe},
    {"FaceStatus"s, FaceProbe},
    {"ForwarderStatus"s, FwdProbe},
    {"Pinger", echoProbe}
};
