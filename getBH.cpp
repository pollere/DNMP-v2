/*
 * getBH-client.cpp: prototype black hole DNMP client
 *
 * Copyright (C) 2019-2020 Pollere, Inc.
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
 *  DNMP is not intended as production code. 
 *  More information on DNMP is available from info@pollere.net
 */

#include <getopt.h>
#include <charconv>
#include <functional>
#include <iostream>
#include <chrono>

/* The CRshim object in CRshim.hpp provides the Command/Reply API from
 * DNMP applications to the PubSub sync protocol, syncps.
 */
#include "CRshim.hpp"

using namespace std::chrono;
using std::to_string;

/* Blackhole utility command-line DNMP Client.
 *    getBH -p prefix_name -w maximum_wait_time_for_reply -t target -i interval
 *      where the -w and -t arguments are not required (have defaults)
 *      the w argument sets the amount of time to wait for all responders
 * This is not exactly the same as the blackhole utility described in the paper
 */

// handles command line
static struct option opts[] = {
    {"prefix", required_argument, nullptr, 'p'},
    {"target", required_argument, nullptr, 't'},
    {"wait", required_argument, nullptr, 'w'},
    {"interval", required_argument, nullptr, 'i'},
    {"debug", no_argument, nullptr, 'd'},
    {"help", no_argument, nullptr, 'h'}
};
static void usage(const char* cname)
{
    std::cerr << "usage: " << cname << " [flags] -p probe_name -t target\n";
}
static void help(const char* cname)
{
    usage(cname);
    std::cerr << " flags:\n"
           "  -p |--prefix name     prefix name\n"
           "  -t |--target name    probe target: local|all|name\n"
           "\n"
           "  -w |--wait time      longest time to wait for a reply (ms)\n"
           "  -i |--interval       time between requests (sec)\n"
           "  -d |--debug          enable debugging output\n"
           "  -h |--help           print help then exit\n";
}

static int debug{0};
static int nReply = 0;     //reply counter
static int nBH = 0;        //blackhole counter
static nanoseconds interval = seconds(1);
static nanoseconds replyWait = seconds(3);
static std::string target("all");  //default
static std::string prefix;
static Timer timer;

/*
 * bhFinish is the callback function set in the call to issueCmd
 * and is also called if the target is local and just one NOD
 * so that the client will exit.
*/

static void bhFinish()
{
    std::cout << "Blackhole Utility finished with " << nReply <<
            " NODs replying and " << nBH << " blackhole(s)" << std::endl;
    exit(0);
}

/*
 * blackholeReply is the callback function whenever a reply is
 *  received from a NOD that received the nod/all/command/RIB/prefix
 */
void blackholeReply(const Reply& pub, CRshim& shim)
{
    // Using the reply timestamps to print client-to-nod & nod-to-client times
    std::cout << "Reply from " << pub["rSrcId"].toEscapedString()
              << " took (sec): "
              << "to NOD=" + to_string(pub.timeDelta("rTS", "cTS"))
              << ", from NOD=" + to_string(pub.timeDelta("rTS")) << std::endl;
    nReply++;
    const auto& c = pub.getContent();
    if(c.size() != 0) {
        std::string f(c.toRawStr());
        f = f.substr(0, f.find("\n"));
        std::cout << "\tHas route to: " << f << std::endl;
    } else {
        std::cout << "\tDoes not have a route to prefix" << std::endl;
        nBH++;
    }
    if (target == "local") {
        bhFinish();     //only get one reply
    }
    // wait for possible more replies - bhFinish() is called after timeout
    return;
}

/*
 * send a command and schedule replyWait timeout
 */
void sendCommand(CRshim& shim)
{
    shim.issueCmd("RIB", prefix, blackholeReply);
    timer = shim.schedule(replyWait, [](){ bhFinish(); });
}

/*
 * main for DNMP BlackHole Client
 * getBH -p <prefix>
 */
int main(int argc, char* argv[])
{
    // parse input line, exit if not a good probe directive
    if (argc <= 1) {
        help(argv[0]);
        return 1;
    }
    for (int c;
         (c = getopt_long(argc, argv, "p:t:w:dh", opts, nullptr)) != -1;) {
        switch (c) {
            double rdbl;
        case 'p':
            prefix = optarg;
            break;
        case 't':
            target = optarg;
            break;
        case 'w':
             rdbl = std::stod(optarg);
            if (rdbl >= 0.1) {
                replyWait = nanoseconds((int)(rdbl * 1e9));
            }

            break;
        case 'i':
            rdbl = std::stod(optarg);
            if (rdbl >= 0.01) {
                interval = nanoseconds((int)(rdbl * 1e9));
            }
            break;
        case 'd':
            ++debug;
            break;
        case 'h':
            help(argv[0]);
            exit(0);
        }
    }
    if (optind < argc || prefix.empty()) {
        usage(argv[0]);
        return 1;
    }
    LOG("Blackhole utility for prefix: " + prefix);

    try {
        // make a CRshim with this target
        CRshim s(target);
        // builds and publishes command and waits for reply
        sendCommand(s);
        s.run();
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
    }
}
