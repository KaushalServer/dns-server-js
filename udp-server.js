const dgram = require("dgram");

const { parseDnsMessage } = require("./parser.js")
const { buildDnsResponse } = require("./response.js")

const server = dgram.createSocket("udp4")
const upstream = dgram.createSocket("udp4")

const pendingRequests = new Map();

const UPSTREAM_DNS = "1.1.1.1" // Upstream forwarding
const UPSTREAM_PORT = 53
const UPSTREAM_TIMEOUT = 3000 // 3 secs

const SERVER_PORT = 1053;
const SERVER_IP = "127.0.0.1";

const records = {
    "ggle.com": "142.250.182.206",
    "ele.com": "93.184.216.34",
    "localhost": "127.0.0.1"
};

const cache = new Map();

function generateTransactionId(){
    let transactionId

    do{
        transactionId = Math.floor(Math.random() * 65536)
    } while (pendingRequests.has(transactionId))

    return transactionId
}

function getCachedResponse(domain){
    const entry = cache.get(domain)

    if(!entry){
        return null
    }

    const remainingMs = entry.expiresAt - Date.now()

    if(remainingMs <=0){
        console.log("Cache expired: ", domain);
        cache.delete(domain)
        return null
    }

    const remainingTtl = Math.ceil(remainingMs / 1000)
    // cache expired
    // if(Date.now() >= entry.expiresAt){
    //     console.log("Cache expired: ", domain);

    //     cache.delete(domain)

    //     return null
    // }

    console.log("CACHE HIT: ", domain, "| Remaining TTL: ", remainingTtl);

    return {
        response: entry.response,
        ttl: remainingTtl
    }
}
// ####################################################
// CACHE STORE
// ####################################################

function storeCache(domain, response, ttl){
    const expiresAt = Date.now() + ttl * 1000

    cache.set(domain, {
        response, expiresAt
    })

    console.log("Cached: ", domain, "| TTL: ", ttl, "seconds");
    
}

function getRcodeName(rcode) {
    const codes = {
        0: "NOERROR",
        1: "FORMERR",
        2: "SERVFAIL",
        3: "NXDOMAIN",
        4: "NOTIMP",
        5: "REFUSED",
    };

    return codes[rcode] || `UNKNOWN (${rcode})`;
}

function updateResponseTtl(buffer, ttl){
    const dnsMessage = parseDnsMessage(buffer)

    // Update Answer TTL
    // let offset = header.questionEndOffset
    for( const answer of dnsMessage.answers){
        buffer.writeUInt32BE(ttl, answer.ttlOffset)
    }

    // Update Authority TTL
}

// ###########################################
// UDP SERVER
// ###########################################

server.on("message", (message, remote) => {
    console.log("\n========== Packet received! ==========\n");

    try {

        const dnsMessage = parseDnsMessage(message)

        const question = dnsMessage.questions[0] // dynamically fixing names and ip

        if (!question) {
            console.error("No DNS question found");

            return;
        }

        const domain = question.domain.toLowerCase()
        // cacheKey can be used for security
        const cacheKey =
            `${domain}:${question.type}:${question.classCode}`;

        console.log(
            "Requested domain:",
            domain
        );

        // const cached = cache.get(domain)
        // ========================================
        // CACHE LOOKUP
        // ========================================

        const cachedResponse = getCachedResponse(cacheKey);

        if (cachedResponse) {

            const response = Buffer.from(cachedResponse.response)

            response.writeUInt16BE(
                dnsMessage.header.transactionId, 0
            )

            updateResponseTtl(
                response,
                cachedResponse.ttl
            )

            server.send(
                response,
                remote.port,
                remote.address,
                (error) => {
                    if (error) {
                        console.error("Cached response send error:", error);
                        return;
                    }

                    console.log("Cached DNS response sent!");
                }
            );

            return;
        }

        console.log("Cache MISS:", domain);

        // Checking IP locally

        const ip = records[domain];

        if(ip){
            console.log("Resolved locally: ", ip);

            const response = buildDnsResponse(dnsMessage, ip)

            server.send(
                response,
                remote.port,
                remote.address,
                (error) => {

                if (error) {
                    console.error(
                    "Response send error:",
                    error
                    );
                    return;
                }

                console.log(
                    "Local DNS response sent!!"
                    );
                }
            );
            return
        }

        // UPSTREAM Forwarding
        console.log("\n Domain not found locally.");

        // console.log("Forwarding query to upstream DNS:- ", UPSTREAM_DNS);
        const transactionId = generateTransactionId()

        // logging upstream transactionId and header transactionId
        console.log(`Client TXID: ${dnsMessage.header.transactionId} || Upstream TXID: ${transactionId}`);

        const timeout = setTimeout(() => {
            console.error(`Upstream DNS timeout for transaction ${transactionId}`)

            pendingRequests.delete(transactionId)
        }, UPSTREAM_TIMEOUT)

        pendingRequests.set(
            transactionId, {
                address: remote.address,
                port: remote.port,
                domain,
                cacheKey,
                clientTransactionId: dnsMessage.header.transactionId,
                timeout
            }
        )

        // console.log("Tracking transaction: ", transactionId);

        console.log("Forwarding to: ", UPSTREAM_DNS);

        const upstreamRequest = Buffer.from(message);

        upstreamRequest.writeUInt16BE(
            transactionId,
            0
        );

        upstream.send(
            upstreamRequest,
            UPSTREAM_PORT, 
            UPSTREAM_DNS,
            (error) => {
                if(error) {
                    console.error("Upstream send error: ", error);
                    clearTimeout(timeout)
                    pendingRequests.delete(transactionId)
                    return
                }
                console.log("Query forwarded successfully!!");
            }
        )

    } catch (error) {
        console.error("\n DNS parsing failed: ");
        console.error(error.message);
    }

});

server.on("listening", () => {
    const address = server.address();

    console.log("UDP server started");
    console.log("IP:", address.address);
    console.log("Port:", address.port);
});

upstream.on("message", (response, remote) => {
    console.log("\n========== UPSTREAM RESPONSE ==========\n");

    console.log("Upstream IP: ", remote.address);

    console.log("Upstream Port: ", remote.port);

    console.log("\nResponse Hex: ", response.toString("hex"));

    try {

            const dnsResponse =
                parseDnsMessage(response);

            console.dir(
                dnsResponse,
                {
                    depth: null
                }
            );

            console.log("DNS RCODE: ", dnsResponse.flags.rcode);

            // rcode
            const rcode = dnsResponse.flags.rcode

            const rcodeName = getRcodeName(rcode)

            const transactionId =
                dnsResponse.header.transactionId;

            const client =
                pendingRequests.get(transactionId); // simple

            if (!client) {

                console.error(
                    "No client found for transaction:",
                    transactionId
                );

                return;
            }

            if (!dnsResponse.flags.isResponse) {
                console.error(
                    `Invalid upstream packet: transaction ${transactionId} is not a DNS response`
                );

                return;
            }

            if (
                !dnsResponse.questions.length ||
                dnsResponse.questions[0].domain.toLowerCase() !== client.domain
            ) {
                console.error(
                    `Invalid upstream response: domain mismatch for transaction ${transactionId}`
                );

                return;
            }

            console.log(
                `Received upstream TXID: ${transactionId} | Restoring client TXID: ${client.clientTransactionId}`
            );

            // Request completed successfully
            clearTimeout(client.timeout)
            pendingRequests.delete(transactionId)

            if (rcode !== 0) {
                console.log(
                    `Upstream returned ${rcodeName} for ${client.domain}`
                );
            }

            clearTimeout(client.timeout)
            const answer = dnsResponse.answers[0]

            // Temp
            console.log("Total answers: ", dnsResponse.answers.length);
            dnsResponse.answers.forEach((answer, index) => {
                console.log(
                    `Answer ${index + 1} :`, answer.address, "| TTL: ", answer.ttl        
                );
            });

            // handling cache
            if(rcode === 0){
                const aRecords = dnsResponse.answers.filter(
                    answer =>
                        ((answer.type === 1 &&
                        answer.dataLength === 4) || (answer.type === 28 && answer.dataLength === 16) || (answer.type  === 5 )) &&
                    answer.ttl > 0
                );

                if (aRecords.length > 0) {

                    const ttl = Math.min(
                        ...aRecords.map(answer => answer.ttl)
                    );

                    console.log(
                        `Found ${aRecords.length} cacheable record(s)`
                    );

                    storeCache(
                        client.cacheKey, response, answer.ttl
                    )

                } else {
                    console.log("NOERROR but non-cacheable record");

                }
            } else if(rcode === 3){
                // SOA
                const soaRecord = dnsResponse.authority.find(
                    record => record.type === 6
                );

                if (soaRecord && soaRecord.address) {
                    const negativeTtl = Math.min(
                        soaRecord.ttl,
                        soaRecord.address.minimum
                    );

                    if(negativeTtl > 0){
                        storeCache(client.cacheKey, response, negativeTtl)

                        console.log(`Cached NXDOMAIN: ${client.domain} | TTL: ${negativeTtl} seconds`);
                    } else {
                        console.log(`NXDOMAIN not cached: invalid negative TTL for ${client.domain}`);

                    }

                } else {
                    console.log(`NXDOMAIN not cached: SOA record missing for${client.domain}`);

                }
            } else {
                // DNS error response
                console.log(`Not caching ${rcodeName} response for ${client.domain}`);
            }

            console.log(
                "\nForwarding upstream response to:"
            );

            console.log(
                "IP:",
                client.address
            );

            console.log(
                "Port:",
                client.port
            );

            response.writeUInt16BE(
                client.clientTransactionId,
                0
            );

            server.send(
                response,
                client.port,
                client.address,
                (error) => {

                    if (error) {
                        console.error(
                            "Client response error:",
                            error
                        );

                        return;
                    }

                    console.log(
                        "\nUpstream response forwarded to client!"
                    );
                    pendingRequests.delete(
                        transactionId
                    );
                }
            );

        } catch (error) {

            // preventing broken upstream packet from leaving stale state around
            console.error(
                "Upstream response parsing failed:",
                error.message
            );

            if(response.length >= 2){

                const transactionId = response.readUInt16BE(0)
                const client = pendingRequests.get(transactionId)

                if(client){
                    clearTimeout(client.timeout)
                    pendingRequests.delete(transactionId)

                    console.log(`Removed pending request for transaction ${transactionId}`);
                }
            }
        }
})

// socket failure
upstream.on("error", (error) => {
    console.error("Upstream DNS socket error: ", error.message);

    // cleaning pending requests
    for (const [transactionId, client] of pendingRequests) {
        clearTimeout(client.timeout)
        pendingRequests.delete(transactionId)

        console.log(`Removed pending request ${transactionId} due to upstream socket error`);
    }
})

server.on("error", (error) => {
    console.error("Server error:", error);
    server.close();
});

server.bind(SERVER_PORT, SERVER_IP);