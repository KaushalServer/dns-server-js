function buildDnsResponse(query, ip){

    const questionStart = 12
    const questionEnd = query.questionEndOffset

    const questionLength = questionEnd - questionStart

    const answerLength = 16

    // const buffer = Buffer.alloc(44) // this static line is the problem
    const buffer = Buffer.alloc(12 + questionLength + answerLength)
    const transactionId = query.header.transactionId
    // const transactionId

    // transaction Id
    buffer.writeUInt16BE(transactionId, 0)

    // Flags
    buffer.writeUInt16BE(0x8180, 2)

    // Questions
    buffer.writeUInt16BE(1,4)

    // Answers
    buffer.writeUInt16BE(1,6)

    // Authority
    buffer.writeUInt16BE(0,8)

    // Additional
    buffer.writeUInt16BE(0,10)

    // query.buffer.copy(buffer, 12, 12, 28) // this static line is the problem

    query.buffer.copy(buffer, 12, questionStart, questionEnd)

    // Answer

    let answerOffset = questionEnd
    // Name compression
    buffer.writeUInt16BE(0xc00c, answerOffset)
    answerOffset += 2

    // Type A
    buffer.writeUInt16BE(1, answerOffset)
    answerOffset += 2

    // Class -> IN
    buffer.writeUInt16BE(1, answerOffset)
    answerOffset += 2

    // TTL -> 71 seconds
    buffer.writeUInt32BE(71, answerOffset)
    answerOffset += 4

    // RDATA length -> 4 bytes
    buffer.writeUInt16BE(4, answerOffset)
    answerOffset += 2

    // IP
    const ipBytes = ip.split(".").map(Number);
    console.log(ipBytes);

    buffer[answerOffset++] = ipBytes[0];
    buffer[answerOffset++] = ipBytes[1];
    buffer[answerOffset++] = ipBytes[2];
    buffer[answerOffset++] = ipBytes[3];

    return buffer
}

module.exports = {
    buildDnsResponse,
}