const { parseDnsMessage } = require("./parser.js")

const dgram = require("dgram");

const socket = dgram.createSocket("udp4");

const upstreamIP = "1.1.1.1";
const upstreamPort = 53;

// Our existing google.com DNS query
const query = Buffer.from(
    "1d0d0100000100000000000006676f6f676c6503636f6d0000010001",
    "hex"
);

socket.on("message", (response, remote) => {

    console.log("\n========== UPSTREAM RESPONSE ==========\n");

    console.log("From:");
    console.log("IP:", remote.address);
    console.log("Port:", remote.port);

    console.log("\nRaw response:");
    console.log(response);

    console.log("\nHex:");
    console.log(response.toString("hex"));

    try{
        const parsed = parseDnsMessage(response)

        console.log("\n========== PARSED RESPONSE ==========\n");
        
        console.dir(parsed, {
            depth: null
        });
        
    } catch (error) {
        console.error("Response parsing failed:", error.message);
    }

    socket.close();
});

socket.on("error", (error) => {
    console.error("UDP error:", error);
    socket.close();
});

socket.send(
    query,
    upstreamPort,
    upstreamIP,
    (error) => {

        if (error) {
            console.error("Send error:", error);
            socket.close();
            return;
        }

        console.log(
            "DNS query sent to upstream:",
            upstreamIP
        );
    }
);