rule win_amadey {

    meta:
        author          = "Johannes Bader @viql"
        version         = "v1.0"
        tlp             = "TLP:WHITE"
        date            = "2022-11-17"
        description     = "matches unpacked Amadey samples"
        malpedia_family = "win.amadey"
        hash_md5        = "25cfcfdb6d73d9cfd88a5247d4038727"
        hash_sha1       = "912d1ef61750bc622ee069cdeed2adbfe208c54d"
        hash_sha256     = "03effd3f94517b08061db014de12f8bf01166a04e93adc2f240a6616bb3bd29a"

    strings:
        $pdb  = "\\Amadey\\Release\\Amadey.pdb" 
        /*  Amadey uses multiple hex strings to decrypt the strings, C2 traffic 
            and as identification. The preceeding string 'stoi ...' is added to 
            improve performance. 
        */
        $keys = /stoi argument out of range\x00\x00[a-f0-9]{32}\x00{1,16}[a-f0-9]{32}\x00{1,4}[a-f0-9]{6}\x00{1,4}[a-f0-9]{32}\x00/

    condition:
        uint16(0) == 0x5A4D and 
        (
            $pdb or $keys
        )
}
