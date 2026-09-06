// const buffer = Buffer.from(
//     "1d0d8180000100010000000006676f6f676c6503636f6d0000010001c00c000100010000004700048efab6ce",
//     "hex"
// );

// ============================================================
// DNS HEADER
// ============================================================

function parseHeader(buffer) {
    if (buffer.length < 12) {
        throw new Error("Invalid DNS packet: header is incomplete");
    }

    return {
        transactionId: buffer.readUInt16BE(0),
        flags: buffer.readUInt16BE(2),
        questions: buffer.readUInt16BE(4),
        answers: buffer.readUInt16BE(6),
        authority: buffer.readUInt16BE(8),
        additional: buffer.readUInt16BE(10),
    };
}

// ============================================================
// DNS FLAGS
// ============================================================

function parseFlags(flags) {
    return {
        isResponse: (flags & 0x8000) !== 0,
        opcode: (flags >> 11) & 0x0f,
        authoritative: (flags & 0x0400) !== 0,
        truncated: (flags & 0x0200) !== 0,
        recursionDesired: (flags & 0x0100) !== 0,
        recursionAvailable: (flags & 0x0080) !== 0,
        rcode: flags & 0x000f,
    };
}

// ============================================================
// DNS DOMAIN NAME
// ============================================================

function readDomain(buffer, offset) {
    const labels = [];
    let originalOffset = offset;
    let jumped = false;

    while (true) {
        if (offset >= buffer.length) {
            throw new Error(
                "Invalid DNS packet: domain exceeds packet length"
            );
        }

        const length = buffer[offset];

        // ----------------------------------------------------
        // Compression pointer
        // ----------------------------------------------------

        if ((length & 0xc0) === 0xc0) {
            if (offset + 1 >= buffer.length) {
                throw new Error(
                    "Invalid DNS packet: incomplete pointer"
                );
            }

            const secondByte = buffer[offset + 1];

            const pointerOffset =
                ((length & 0x3f) << 8) | secondByte;

            if (!jumped) {
                originalOffset = offset + 2;
            }

            offset = pointerOffset;
            jumped = true;

            continue;
        }

        // ----------------------------------------------------
        // End of domain
        // ----------------------------------------------------

        if (length === 0) {
            offset++;

            return {
                domain: labels.join("."),
                offset: jumped ? originalOffset : offset,
            };
        }

        // ----------------------------------------------------
        // Validate label
        // ----------------------------------------------------

        if (length > 63) {
            throw new Error(
                "Invalid DNS packet: invalid label length"
            );
        }

        if (offset + 1 + length > buffer.length) {
            throw new Error(
                "Invalid DNS packet: label exceeds packet length"
            );
        }

        // ----------------------------------------------------
        // Read label
        // ----------------------------------------------------

        const label = buffer
            .subarray(
                offset + 1,
                offset + 1 + length
            )
            .toString("ascii");

        labels.push(label);

        offset += length + 1;
    }
}

// ============================================================
// DNS QUESTION
// ============================================================

function parseQuestion(buffer, offset) {
    const result = readDomain(buffer, offset);

    const type = buffer.readUInt16BE(result.offset);
    const classCode = buffer.readUInt16BE(result.offset + 2);

    return {
        question: {
            domain: result.domain,
            type,
            classCode,
        },

        offset: result.offset + 4,
    };
}

// ============================================================
// DNS ANSWER
// ============================================================

function parseAnswer(buffer, offset) {
    const result = readDomain(buffer, offset);

    const type = buffer.readUInt16BE(result.offset);
    const classCode = buffer.readUInt16BE(result.offset + 2);

    const ttl = buffer.readUInt32BE(result.offset + 4);

    const dataLength = buffer.readUInt16BE(result.offset + 8);

    const dataStart = result.offset + 10;
    const dataEnd = dataStart + dataLength;

    if (dataEnd > buffer.length) {
        throw new Error(
            "Invalid DNS packet: answer data exceeds packet length"
        );
    }

    let address = null;

    if(type === 1 && dataLength === 4){
        // type A -> IPv4
        const addressBytes = buffer.subarray(
            dataStart,
            dataEnd
        );

        address = [...addressBytes].join(".");
    } else if( type === 28 && dataLength === 16){
        // AAAA -> IPv6
        const addressBytes = buffer.subarray(
            dataStart,
            dataEnd
        );

        const parts = []

        for( let i = 0; i < 16; i += 2){
            parts.push(addressBytes.readUInt16BE(i).toString(16))
        }
        address = parts.join(":")
    } else if( type === 5 ){
        // Handling CNAME
        const cnameResult = readDomain(buffer, dataStart)
        address = cnameResult.domain
    } else if( type === 6 ){
        const mnameResult = readDomain(buffer, dataStart)
        const rnameResult = readDomain(buffer, mnameResult.offset)

        const serial = buffer.readUInt32BE(rnameResult.offset)
        const refresh = buffer.readUInt32BE(rnameResult.offset + 4)
        const retry = buffer.readUInt32BE(rnameResult.offset + 8)
        const expire = buffer.readUInt32BE(rnameResult.offset + 12)
        const minimum = buffer.readUInt32BE(rnameResult.offset + 16)

        address = {
            mname: mnameResult.domain,
            rname: rnameResult.domain,
            serial,
            refresh,
            retry,
            expire,
            minimum
        };
    } else {
        // Unsupported record types
        console.log(
            `Unsupported DNS record type: ${type} | Data length: ${dataLength}`
        );
        address = null
    }

    return {
        answer: {
            name: result.domain,
            type,
            classCode,
            ttl,
            ttlOffset: result.offset + 4,
            dataLength,
            address,
        },

        offset: dataEnd,
    };
}

// ============================================================
// PARSE COMPLETE DNS MESSAGE
// ============================================================

function parseDnsMessage(buffer) {
    const header = parseHeader(buffer);

    const flags = parseFlags(header.flags);

    let offset = 12;

    // --------------------------------------------------------
    // Questions
    // --------------------------------------------------------

    const questions = [];

    for (let i = 0; i < header.questions; i++) {
        const result = parseQuestion(buffer, offset);

        questions.push(result.question);

        offset = result.offset;
    }

    const questionEndOffset = offset;

    // --------------------------------------------------------
    // Answers
    // --------------------------------------------------------

    const answers = [];

    for (let i = 0; i < header.answers; i++) {
        const result = parseAnswer(buffer, offset);

        answers.push(result.answer);

        offset = result.offset;
    }

    const authority = [];

    for (let i = 0; i < header.authority; i++) {
        const result = parseAnswer(buffer, offset);

        authority.push(result.answer);

        offset = result.offset;
    }

    return {
        header,
        flags,
        questions,
        answers,
        authority,
        buffer,
        questionEndOffset,
    };
}

// ============================================================
// TEST
// ============================================================

// console.log("\n========== RAW BUFFER ==========\n");

// console.log(buffer);

// console.log("\n========== PARSED DNS MESSAGE ==========\n");

// const dnsMessage = parseDnsMessage(buffer);

// console.dir(dnsMessage, {
//     depth: null,
// });

module.exports = {
    parseDnsMessage,
}