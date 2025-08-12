rule LSB_Steganography_Payload_Operations
{
    meta:
        author = "0x12 Dark Development"
        description = "Detects LSB steganography operations for hiding and extracting payload bits in image data"
        date = "2025-08-12"
        reference = "Based on code hiding payloads in PNG LSB"

    strings:
        // Typical masking to clear LSB (hide operation)
        $and_clear_fe = { 80  E? FE }      // AND r/m8, 0xFE

        // Typical masking to read LSB (extract operation)
        $and_read_01  = { 80  E? 01 }      // AND r/m8, 0x01

        // Bit shifts used to position the payload bit (both hide & extract)
        $shr_op       = { C0 E? ?? }       // SHR r/m8, imm8
        $shl_op       = { C0 E? ?? }       // SHL r/m8, imm8

        // Combining the cleared byte with payload bit
        $or_op        = { 08 ?? }          // OR r/m8, r8 or immediate

    condition:
        (
            // Likely hide operation
            $and_clear_fe and $or_op and $shr_op
        )
        or
        (
            // Likely extract operation
            $and_read_01 and ($shr_op or $shl_op)
        )
}
