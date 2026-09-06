const buffer = Buffer.from("1d0d8180000100010000000006676f6f676c6503636f6d0000010001c00c000100010000004700048efab6ce",
    "hex"
);

console.log(buffer);

const transactionId = buffer.readUInt16BE(0)
const flags = buffer.readUInt16BE(2)
const questions = buffer.readUInt16BE(4)
const answers = buffer.readUInt16BE(6)
const authority = buffer.readUInt16BE(8)
const additional = buffer.readUInt16BE(10)

// console.log(transactionId);
// console.log(transactionId.toString(16));
console.log({
    transactionId: transactionId.toString(16),
    flags: flags.toString(16),
    questions,
    answers,
    authority,
    additional
});

// function readDomain(buffer, offset) {
//     const labels = [];

//     while (true) {
//         const length = buffer[offset];

//         if (length === 0) {
//             offset++;
//             break;
//         }

//         const label = buffer
//             .subarray(offset + 1, offset + 1 + length)
//             .toString("ascii");

//         labels.push(label);

//         offset += length + 1;
//     }

//     return {
//         domain: labels.join("."),
//         offset
//     };
// }

function readDomain(buffer, offset) {
    const labels = [];
    let originalOffset = offset;
    let jumped = false;

    while (true) {
        if (offset >= buffer.length) {
            throw new Error("Invalid DNS packet: domain exceeds packet length");
        }

        const length = buffer[offset];

        // DNS compression pointer
        if ((length & 0xc0) === 0xc0) {
            if (offset + 1 >= buffer.length) {
                throw new Error("Invalid DNS packet: incomplete pointer");
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

        // End of domain
        if (length === 0) {
            offset++;

            if (jumped) {
                return {
                    domain: labels.join("."),
                    offset: originalOffset
                };
            }

            return {
                domain: labels.join("."),
                offset
            };
        }

        // Invalid label
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

// const result = readDomain(buffer, 12);

const { domain, offset } = readDomain(buffer, 12);

const type = buffer.readUInt16BE(offset);
const classCode = buffer.readUInt16BE(offset + 2);

console.log({
    domain,
    type,
    classCode
});

const isResponse = (flags & 0x8000) !== 0;
const opcode = (flags >> 11) & 0x0f;
const authoritative = (flags & 0x0400) !== 0;
const truncated = (flags & 0x0200) !== 0;
const recursionDesired = (flags & 0x0100) !== 0;
const recursionAvailable = (flags & 0x0080) !== 0;
const rcode = flags & 0x000f;

console.log({
    isResponse,
    opcode,
    authoritative,
    truncated,
    recursionDesired,
    recursionAvailable,
    rcode
});

const answerOffset = question.offset;

const answerName = readDomain(buffer, answerOffset);

const answerType = buffer.readUInt16BE(answerName.offset);
const answerClass = buffer.readUInt16BE(answerName.offset + 2);

const ttl = buffer.readUInt32BE(answerName.offset + 4);

const dataLength = buffer.readUInt16BE(answerName.offset + 8);

const addressBytes = buffer.subarray(
    answerName.offset + 10,
    answerName.offset + 10 + dataLength
);

const address = [...addressBytes].join(".");

console.log({
    name: answerName.domain,
    type: answerType,
    classCode: answerClass,
    ttl,
    dataLength,
    address
});