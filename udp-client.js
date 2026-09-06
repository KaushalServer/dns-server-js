const dgram = require("dgram");

const { parseDnsMessage } = require("./parser.js")

const client = dgram.createSocket("udp4");

// const message = Buffer.from("1d0d010000010000000000000667697468756203636f6d0000010001", // 222701000001000000000000076578616d706c6503636f6d0000010001 // 1d0d0100000100000000000006676f6f676c6503636f6d0000010001
//     "hex");
// github hex - 1d0d010000010000000000000667697468756203636f6d0000010001

function buildDnsQuery(domain, transactionId, type = 1, classCode = 1) {
    const labels = domain.split(".");

    const domainParts = [];

    for (const label of labels) {
        domainParts.push(
            Buffer.from([label.length])
        );

        domainParts.push(
            Buffer.from(label)
        );
    }

    // End of domain name
    domainParts.push(Buffer.from([0]));

    // DNS Header = 12 bytes
    // Question type + class = 4 bytes
    const domainBuffer = Buffer.concat(domainParts);

    const buffer = Buffer.alloc(
        12 + domainBuffer.length + 4
    );

    // Transaction ID
    buffer.writeUInt16BE(transactionId, 0);

    // Flags
    buffer.writeUInt16BE(0x0100, 2);

    // Questions
    buffer.writeUInt16BE(1, 4); // 

    // Answers
    buffer.writeUInt16BE(0, 6);

    // Authority
    buffer.writeUInt16BE(0, 8);

    // Additional
    buffer.writeUInt16BE(0, 10);

    // Domain
    domainBuffer.copy(buffer, 12);

    const questionOffset =
        12 + domainBuffer.length;

    // Type A
    buffer.writeUInt16BE(type, questionOffset);

    // Class IN
    buffer.writeUInt16BE(1, questionOffset + 2);

    return buffer;
}

// const googleQuery =
//     buildDnsQuery("google.com", 1001, 1);
// const googleQuery =
//     buildDnsQuery("google.com", 1002, 28); // AAAA 
// const googleQuery =
//     buildDnsQuery("google.com", 1003, 1); //
const googleQuery =
    buildDnsQuery("google.com", 1004, 28); // AAAA 

const githubQuery =
    buildDnsQuery("www.google.com", 1005, 5);

const exampleQuery =
    buildDnsQuery("google.com", 1006, 1);

client.on(
    "message", (response, remote) => {
        console.log("\n========== RESPONSE RECEIVED ==========\n");

        console.log("From:");
        console.log("IP:", remote.address);
        console.log("Port:", remote.port);

        console.log("\nRaw response:");
        console.log(response);

        console.log("\nHex:");
        console.log(response.toString("hex"));

        try{
            const parsedResponse = parseDnsMessage(response)

            console.log("\n========== PARSED RESPONSE ==========\n");

            console.dir(parsedResponse, {
                depth: null
            })

        } catch (error) {
            console.error("\nResponse parsing failed", error.message);
        }

        // client.close();
    }
)

// client.send(
//     googleQuery,
//     1053,
//     "127.0.0.1",
//     (error) => {
//         if (error) {
//             console.error("Send error:", error);
//             // client.close();
//             return;
//         }

//         console.log("Message sent!");

//         // client.close();
//     }
// );

client.send(
    githubQuery,
    1053,
    "127.0.0.1",
    (error) => {
        if (error) {
            console.error("Send error:", error);
            // client.close();
            return;
        }

        console.log("Message sent!");

        // client.close();
    }
);

// client.send(
//     exampleQuery,
//     1053,
//     "127.0.0.1",
//     (error) => {
//         if (error) {
//             console.error("Send error:", error);
//             // client.close();
//             return;
//         }

//         console.log("Message sent!");

//         // client.close();
//     }
// );

// With transactionId the requests are being overwritten by the other