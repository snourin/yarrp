/****************************************************************************
 * Copyright (c) 2016-2024 Robert Beverly <rbeverly@cmand.org>
 * All rights reserved.
 *
 * Program:     $Id: yaarp.cpp $
 * Description: yarrp.  https://www.cmand.org/yarrp
 *              indent -i4 -nfbs -sob -nut -ldi1 yarrp.cpp
 *
 * Attribution: R. Beverly, "Yarrp'ing the Internet: Randomized High-Speed
 *              Active Topology Discovery", Proceedings of the ACM SIGCOMM
 *              Internet Measurement Conference, November, 2016
 ***************************************************************************/
#include "yarrp.h"

volatile bool startTimeout = false;

template < class TYPE >
void
loop(YarrpConfig * config, TYPE * iplist, Traceroute * trace,
     Patricia * tree, Stats * stats) {
    struct in_addr target;
    struct in6_addr target6;
    uint8_t ttl;
    TTLHisto *ttlhisto = NULL;
    Status *status = NULL;
    char ptarg[INET6_ADDRSTRLEN];
    double prob, flip;
    int *asn;

    //adaptive timing to hit target rate
    uint64_t count = 0;
    uint64_t last_count = count;
    double last_time = now();
    uint32_t delay = 0;
    int interval = 0;
    volatile int vi;
    struct timespec ts, rem;
    double send_rate = (double)config->rate;
    const double slow_rate = 50;
    long nsec_per_sec = 1000 * 1000 * 1000;
    long long sleep_time = nsec_per_sec;

    if (config->rate > 0) {
        delay = 10000;
        if (send_rate < slow_rate) {
            //set the inital time difference
            sleep_time = nsec_per_sec / send_rate;
            last_time = now() - (1.0 / send_rate);
        } else {
            //estimate initial rate
            for (vi = delay; vi--;);
            delay *= 1 / (now() - last_time) / (config->rate);
            interval = (config->rate) / 20;
            last_time = now();
        }
    }

    stats->to_probe = iplist->count();

    debug(LOW, "[loop] Entering the probing loop");

    while (true) {
        /* Grab next target/ttl pair from permutation */
        if (config->ipv6) {
            if ((iplist->next_address(&target6, &ttl)) == 0)
                break;
        } else {
            if ((iplist->next_address(&target, &ttl)) == 0)
                break;
        }
        /* TTL control enforcement */
        ttl += config->minttl;
        if (ttl > config->maxttl) {
            continue;
        }
        /* Running w/ a biased TTL probability distribution */
        if (config->poisson) {
            prob = poisson_pmf(ttl, config->poisson);
            flip = zrand();
            //cout << "TTL: " << (int)ttl << " PMF: " << prob << " flip: " << flip << endl;
            if (flip > prob)
                continue;
        }
        /* Send probe only if outside discovered neighborhood */
        if (ttl < config->ttl_neighborhood) {
            ttlhisto = trace->ttlhisto[ttl];
            if (ttlhisto->shouldProbeProb() == false) {
                //cout << "TTL Skip: " << inet_ntoa(target) << " TTL: " << (int)ttl << endl;
                stats->nbr_skipped++;
                continue;
            }
            ttlhisto->probed(trace->elapsed());
        }
        /* Only send probe if destination is in BGP table */
        if (config->bgpfile or config->blocklist) {
            if (config->ipv6) {
                asn = (int *)tree->get(target6);
            } else {
                asn = (int *)tree->get(target.s_addr);
            }
            if (verbosity >= HIGH)
                inet_ntop(AF_INET, &target, ptarg, INET6_ADDRSTRLEN);
            if (asn == NULL) {
                debug(DEBUG, "BGP Skip: " << ptarg << " TTL: " << (int)ttl);
                stats->bgp_outside++;
                continue;
            }
            if (*asn == 0) {
                debug(HIGH, ">> Address in blocklist: " << ptarg << " TTL: " << (int)ttl);
                continue;
            } else {
                debug(DEBUG, ">> Prefix: " << ptarg << " ASN: " << *asn);
            }
#if 0
                status = (Status *) tree->get(target.s_addr);
                if (status) {
                    status->probed(ttl, trace->elapsed());
                } else {
                    stats->bgp_outside++;
                    continue;
                }
#endif
        }
        /* Passed all checks, continue and send probe */
        if (not config->testing) {
            if (config->ipv6)
                trace->probe(target6, ttl);
            else
                trace->probe(target.s_addr, ttl);
        } else if (verbosity > HIGH) {
            if (config->ipv6)
                trace->probePrint(target6, ttl);
            else
                trace->probePrint(&target, ttl);
        }
        stats->count++;
        //increment counter again because we send two packets for this probe type
        if (config->type == TR_TCP_SYN_PSHACK) { 
            stats->count++;
        }
        /* Progress printer */
        if ((verbosity >= LOW) and
            (iplist->count() > 10000) and
            (stats->count % (iplist->count() / 1000) == 0)) {
            stats->terse();
        }

        /* Calculate sleep time based on scan rate */
        if (config->rate) {
            send_rate = (double)config->rate;
            if (count && delay > 0) {
                if (send_rate < slow_rate) {
                    double t = now();
                    double last_rate = (1.0 / (t - last_time));

                    sleep_time *= ((last_rate / send_rate) + 1) / 2;
                    ts.tv_sec = sleep_time / nsec_per_sec;
                    ts.tv_nsec = sleep_time % nsec_per_sec;
                    while (nanosleep(&ts, &rem) == -1) {
                    }
                    last_time = t;
                } else {
                    for (vi = delay; vi--;);
                    if (!interval || (count % interval == 0)) {
                        double t = now();
                        double multiplier =
                        (double)(count - last_count) /
                        (t - last_time) /
                        (config->rate);
                        uint32_t old_delay = delay;
                        delay *= multiplier;
                        if (delay == old_delay) {
                            if (multiplier > 1.0) {
                                delay *= 2;
                            } else if (multiplier < 1.0) {
                                delay *= 0.5;
                            }
                        }
                        last_count = count;
                        last_time = t;
                    }
                }
            }
        }
        count = stats->count;

        /* Quit if we've exceeded probe count from command line */
        if (stats->count == config->count)
            break;
    }
}

int
sane(YarrpConfig * config) {
    if (not config->testing)
        checkRoot();
    if (config->minttl > config->maxttl)
        fatal("min_ttl must be less than or equal max_ttl");
    if ((config->fillmode > 0) and(config->fillmode < config->maxttl))
        fatal("Fill mode TTL must be larger than max_ttl");
    if (config->ipv6 and not config->testing) {
        if (config->int_name == NULL)
            fatal("IPv6 requires specifying an interface");
    }
    if (config->entire and not config->bgpfile)
        fatal("Entire Internet mode requires BGP table");
    if (config->inlist and config->entire)
        fatal("Cannot run in entire Internet mode with input targets");
    return true;
}

int
main(int argc, char **argv) {
    /* Parse options */
    YarrpConfig config = YarrpConfig();
    config.parse_opts(argc, argv);

    /* Sanity checks */
    sane(&config);

    /* Ensure we're the only Yarrp probing instance on this machine */
    if (config.probe)
        instanceLock(config.instance);

    /* Setup IPv6, if using (must be done before trace object) */
    if (config.ipv6 and not config.testing) {
        if (config.srcmac == NULL || config.dstmac == NULL) {
            LLResolv *ll = new LLResolv();
            ll->gateway();
            ll->mine(config.int_name);
            if (not config.srcmac)
                ll->setSrcMAC(&config.srcmac);
            if (not config.dstmac)
                ll->setDstMAC(&config.dstmac);
            if (config.srcmac == NULL || config.dstmac == NULL) {
                fatal("unable to auto-interpret MAC addresses; use -M, -G");
            }
        }
    }
    /* Initialize subnet list and add subnets from args */
    SubnetList *subnetlist = NULL;
    if (not config.entire and not config.inlist and config.probe) {
        if (config.random_scan)
            subnetlist = new RandomSubnetList(config.maxttl, config.granularity);
        else
            subnetlist = new SubnetList(config.maxttl, config.granularity);
        for (int i = optind; i < argc; i++)
            subnetlist->add_subnet(argv[i], config.ipv6);
        if (0 == subnetlist->count())
            config.usage(argv[0]);
    }
    /* Initialize radix trie, if using */
    Patricia *tree = NULL;
    if (config.ipv6) {
        tree = new Patricia(128);
        if (config.blocklist) {
            debug(LOW, ">> Populating IPv6 blocklist: " << config.blocklist);
            tree->populateBlock(AF_INET6, config.blocklist);
        }
        if (config.bgpfile) {
            debug(LOW, ">> Populating IPv6 trie from: " << config.bgpfile);
            tree->populate6(config.bgpfile);
        } else {
            tree->add(AF_INET6, "::/0", 1);
        }
    } else {
        tree = new Patricia(32);
        if (config.blocklist) {
            debug(LOW, ">> Populating IPv4 blocklist: " << config.blocklist);
            tree->populateBlock(AF_INET, config.blocklist);
        }
        if (config.bgpfile) {
                debug(LOW, ">> Populating IPv4 trie from: " << config.bgpfile);
            //tree->populateStatus(config.bgpfile);
            tree->populate(config.bgpfile);
        } else {
            tree->add("0.0.0.0/0", 1);
        }
    }
    /* Initialize traceroute engine, if not in test mode */
    Stats *stats = new Stats();
    Traceroute *trace = NULL;
    if (config.ipv6)
        trace = new Traceroute6(&config, stats);
    else
        trace = new Traceroute4(&config, stats);

    trace->addTree(tree);

    /* Open output */
    if (config.receive) {
        config.dump();
        /* unlock so listener thread starts */
        trace->unlock();
    }
    /* Start listener if we're only in receive mode */
    if ((not config.probe) and config.receive) {
        if (config.ipv6)
            listener6(trace);
        else
            listener(trace);
    }

    /* Main probing loop */
    if (config.probe) {

        std:ifstream named_pipe(config.named_pipe);

        if (! named_pipe.is_open()) {
            debug(LOW, "Failed to open named pipe: " << config.named_pipe);
            return 1;
        }

        IPList *iplist = NULL;
        do {
            // Print our current configuration
            config.dump();

            debug(LOW, "==== Constructing the IP list ====");
            // Delete the previous iplist
            if (iplist != nullptr) {
                delete iplist;
                iplist = nullptr;
            }

            /* Init target list (individual IPs, *NOT* subnets) from input file */
            if (config.inlist or config.entire) {
                if (config.ipv6)
                    iplist = new IPList6(config.maxttl, config.random_scan, config.entire);
                else
                    iplist = new IPList4(config.maxttl, config.random_scan, config.entire);
                /* randomize permutation key */
                iplist->setkey(config.seed);
                if (config.inlist)
                    iplist->read(config.inlist);
            }

            debug(LOW, "==== Done constructing the IP list ====");

            debug(LOW, "==== Probing chunk beginning... ====");

            if (config.entire or config.inlist) {
                /* Start scanning with current IP list */
                pid_t pid = fork();
                if (pid == 0) { // Child process
                                // Run tcpdump
                    std::string pcap_filename = std::string(config.output) + ".pcap";
                    int pcap_result = execlp("tcpdump", "tcpdump", "-i", "any", "-w", pcap_filename.c_str(), NULL);
                    if (pcap_result == -1) {
                        std::cout << "Failed to run tcpdump" << std::endl;
                    }

                } else if (pid > 0) { // Parent process
                    loop(&config, iplist, trace, tree, stats);
                    debug(LOW, "Probing loop complete. Napping before terminating tcpdump");
                    sleep(120);
                    kill(pid, SIGINT); // Stop tcpdump
                    waitpid(pid, nullptr, 0);
                    debug(LOW, "Successfully stopped tcpdump");
                } else {
                    debug(LOW, "Failed to fork for tcpdump");
                }
            }

            debug(LOW, "==== Probing chunk complete ====");

            /* Dump stats from probe */
            if (config.receive) {
                if (config.output and not config.testing) {
                    stats->dump(trace->config->out);
                    stats->dump(trace->config->tcp_out);
                }
                else
                    stats->dump(stdout);
            }

            /* If just ran uncensored probes, wait 2 minutes for TCB of routers/middleboxes to 
               be cleared before running censored probes */
            const char* uncensored_output = "uncensored";
            if (strstr(config.output, uncensored_output) != NULL) { 
                sleep(2);
            }

            /* Read from the named pipe to get the new set of targets */
            std::cout << std::unitbuf;

            std::string line; 
            std::vector<string> lines;

            // Read first line (input)
            if (std::getline(named_pipe, line)) {
                lines.push_back(line);
            } else {
                debug(LOW, "[error] Missing expected 'input' line from named pipe");
                break;
            }

            if (line == "exit"){
                debug(LOW, "Got 'exit' off of the named pipe; exiting");
                break; // Exit out of this do/while loop
            }

            // Read second line (output)
            if (std::getline(named_pipe, line)) {
                lines.push_back(line);
            } else {
                debug(LOW, "[error] Missing expected 'output' line from named pipe");
                break;
            }

            // Read third line (probe)
            if (std::getline(named_pipe, line)) {
                lines.push_back(line);
            } else {
                debug(LOW, "[error] Missing expected 'probe' line from named pipe");
                break;
            }

            // Read fourth line (instance)
            if (std::getline(named_pipe, line)) {
                lines.push_back(line);
            } else {
                debug(LOW, "[error] Missing expected 'instance' line from named pipe");
                break;
            } 

            const std::string& input = lines[0];
            const std::string& output = lines[1];
            const std::string& probe = lines[2];
            uint8_t instance = uint8_t(std::stoi(lines[3]));

            config.switch_probe(probe.c_str());
            config.switch_target(input.c_str());
            config.switch_output(output);
            config.switch_instance(instance);

            trace->clearHisto();
            trace->initHisto(config.ttl_neighborhood);
            stats->reset();

        } while(true); // main probing loop
    } // if config.probe



    // while (true) {
    //     if (config.probe) {
    //         debug(LOW, ">> Probing begins.");

    //         /* Scan the current IPs */
    //         if (config.entire or config.inlist) {
    //             loop(&config, iplist, trace, tree, stats);
    //         }

    //         /* Enter listening mode for new IPs */
    //         std::cout << "Waiting for new IPs (type 'exit' to quit):" << std::endl;
    //         std::string input;
    //         std::getline(std::cin, input);

    //         if (input == "exit") {
    //             break; // Exit the loop if user types "exit"
    //         }

    //         /* Clear the current IP list and load new IPs */
    //         std::istringstream ip_stream(input);
    //         iplist->read(ip_stream);

    //         std::cout << "New IPs added. Resuming scanning..." << std::endl;
    //     }
    // }
    if (config.receive) {
        debug(LOW, ">> Waiting " << SHUTDOWN_WAIT << "s for outstanding replies...");
        sleep(SHUTDOWN_WAIT);
    }
    // /* Finished, cleanup */
    // if (config.receive) {
    //     if (config.output and not config.testing)
    //         stats->dump(trace->config->out);
    //     else
    //         stats->dump(stdout);
    // }
    delete stats;
    delete trace;
    if (tree)
        delete tree;
    // if (iplist)
    //     delete iplist;
    if (subnetlist)
        delete subnetlist;
}
