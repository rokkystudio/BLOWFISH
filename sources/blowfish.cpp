#include "blowfish.h"

#include <algorithm>
#include <stdexcept>
#include <string_view>

namespace blowfish
{
    namespace
    {
        struct InitialSubkeys
        {
            std::array<std::uint32_t, 18> p = {};
            std::array<std::array<std::uint32_t, 256>, 4> s = {};
        };

        constexpr std::string_view PiHexDigits =
            "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
            "452821E638D01377BE5466CF34E90C6CC0AC29B7C97C50DD3F84D5B5B5470917"
            "9216D5D98979FB1BD1310BA698DFB5AC2FFD72DBD01ADFB7B8E1AFED6A267E96"
            "BA7C9045F12C7F9924A19947B3916CF70801F2E2858EFC16636920D871574E69"
            "A458FEA3F4933D7E0D95748F728EB658718BCD5882154AEE7B54A41DC25A59B5"
            "9C30D5392AF26013C5D1B023286085F0CA417918B8DB38EF8E79DCB0603A180E"
            "6C9E0E8BB01E8A3ED71577C1BD314B2778AF2FDA55605C60E65525F3AA55AB94"
            "5748986263E8144055CA396A2AAB10B6B4CC5C341141E8CEA15486AF7C72E993"
            "B3EE1411636FBC2A2BA9C55D741831F6CE5C3E169B87931EAFD6BA336C24CF5C"
            "7A325381289586773B8F48986B4BB9AFC4BFE81B6628219361D809CCFB21A991"
            "487CAC605DEC8032EF845D5DE98575B1DC262302EB651B8823893E81D396ACC5"
            "0F6D6FF383F442392E0B4482A484200469C8F04A9E1F9B5E21C66842F6E96C9A"
            "670C9C61ABD388F06A51A0D2D8542F68960FA728AB5133A36EEF0B6C137A3BE4"
            "BA3BF0507EFB2A98A1F1651D39AF017666CA593E82430E888CEE8619456F9FB4"
            "7D84A5C33B8B5EBEE06F75D885C12073401A449F56C16AA64ED3AA62363F7706"
            "1BFEDF72429B023D37D0D724D00A1248DB0FEAD349F1C09B075372C980991B7B"
            "25D479D8F6E8DEF7E3FE501AB6794C3B976CE0BD04C006BAC1A94FB6409F60C4"
            "5E5C9EC2196A246368FB6FAF3E6C53B51339B2EB3B52EC6F6DFC511F9B30952C"
            "CC814544AF5EBD09BEE3D004DE334AFD660F2807192E4BB3C0CBA85745C8740F"
            "D20B5F39B9D3FBDB5579C0BD1A60320AD6A100C6402C7279679F25FEFB1FA3CC"
            "8EA5E9F8DB3222F83C7516DFFD616B152F501EC8AD0552AB323DB5FAFD238760"
            "53317B483E00DF829E5C57BBCA6F8CA01A87562EDF1769DBD542A8F6287EFFC3"
            "AC6732C68C4F5573695B27B0BBCA58C8E1FFA35DB8F011A010FA3D98FD2183B8"
            "4AFCB56C2DD1D35B9A53E479B6F84565D28E49BC4BFB9790E1DDF2DAA4CB7E33"
            "62FB1341CEE4C6E8EF20CADA36774C01D07E9EFE2BF11FB495DBDA4DAE909198"
            "EAAD8E716B93D5A0D08ED1D0AFC725E08E3C5B2F8E7594B78FF6E2FBF2122B64"
            "8888B812900DF01C4FAD5EA0688FC31CD1CFF191B3A8C1AD2F2F2218BE0E1777"
            "EA752DFE8B021FA1E5A0CC0FB56F74E818ACF3D6CE89E299B4A84FE0FD13E0B7"
            "7CC43B81D2ADA8D9165FA2668095770593CC7314211A1477E6AD206577B5FA86"
            "C75442F5FB9D35CFEBCDAF0C7B3E89A0D6411BD3AE1E7E4900250E2D2071B35E"
            "226800BB57B8E0AF2464369BF009B91E5563911D59DFA6AA78C14389D95A537F"
            "207D5BA202E5B9C5832603766295CFA911C819684E734A41B3472DCA7B14A94A"
            "1B5100529A532915D60F573FBC9BC6E42B60A47681E6740008BA6FB5571BE91F"
            "F296EC6B2A0DD915B6636521E7B9F9B6FF34052EC585566453B02D5DA99F8FA1"
            "08BA47996E85076A4B7A70E9B5B32944DB75092EC4192623AD6EA6B049A7DF7D"
            "9CEE60B88FEDB266ECAA8C71699A17FF5664526CC2B19EE1193602A575094C29"
            "A0591340E4183A3E3F54989A5B429D656B8FE4D699F73FD6A1D29C07EFE830F5"
            "4D2D38E6F0255DC14CDD20868470EB266382E9C6021ECC5E09686B3F3EBAEFC9"
            "3C9718146B6A70A1687F358452A0E286B79C5305AA5007373E07841C7FDEAE5C"
            "8E7D44EC5716F2B8B03ADA37F0500C0DF01C1F040200B3FFAE0CF51A3CB574B2"
            "25837A58DC0921BDD19113F97CA92FF69432477322F547013AE5E58137C2DADC"
            "C8B576349AF3DDA7A94461460FD0030EECC8C73EA4751E41E238CD993BEA0E2F"
            "3280BBA1183EB3314E548B384F6DB9086F420D03F60A04BF2CB8129024977C79"
            "5679B072BCAF89AFDE9A771FD9930810B38BAE12DCCF3F2E5512721F2E6B7124"
            "501ADDE69F84CD877A5847187408DA17BC9F9ABCE94B7D8CEC7AEC3ADB851DFA"
            "63094366C464C3D2EF1C18473215D908DD433B3724C2BA1612A14D432A65C451"
            "50940002133AE4DD71DFF89E10314E5581AC77D65F11199B043556F1D7A3C76B"
            "3C11183B5924A509F28FE6ED97F1FBFA9EBABF2C1E153C6E86E34570EAE96FB1"
            "860E5E0A5A3E2AB3771FE71C4E3D06FA2965DCB999E71D0F803E89D65266C825"
            "2E4CC9789C10B36AC6150EBA94E2EA78A5FC3C531E0A2DF4F2F74EA7361D2B3D"
            "1939260F19C279605223A708F71312B6EBADFE6EEAC31F66E3BC4595A67BC883"
            "B17F37D1018CFF28C332DDEFBE6C5AA56558218568AB9802EECEA50FDB2F953B"
            "2AEF7DAD5B6E2F841521B62829076170ECDD4775619F151013CCA830EB61BD96"
            "0334FE1EAA0363CFB5735C904C70A239D59E9E0BCBAADE14EECC86BC60622CA7"
            "9CAB5CABB2F3846E648B1EAF19BDF0CAA02369B9655ABB5040685A323C2AB4B3"
            "319EE9D5C021B8F79B540B19875FA09995F7997E623D7DA8F837889A97E32D77"
            "11ED935F166812810E358829C7E61FD696DEDFA17858BA9957F584A51B227263"
            "9B83C3FF1AC24696CDB30AEB532E30548FD948E46DBC312858EBF2EF34C6FFEA"
            "FE28ED61EE7C3C735D4A14D9E864B7E342105D14203E13E045EEE2B6A3AAABEA"
            "DB6C4F15FACB4FD0C742F442EF6ABBB5654F3B1D41CD2105D81E799E86854DC7"
            "E44B476A3D816250CF62A1F25B8D2646FC8883A0C1C7B6A37F1524C369CB7492"
            "47848A0B5692B285095BBF00AD19489D1462B17423820E0058428D2A0C55F5EA"
            "1DADF43E233F70613372F0928D937E41D65FECF16C223BDB7CDE3759CBEE7460"
            "4085F2A7CE77326EA607808419F8509EE8EFD85561D99735A969A7AAC50C06C2"
            "5A04ABFC800BCADC9E447A2EC3453484FDD567050E1E9EC9DB73DBD3105588CD"
            "675FDA79E3674340C5C43465713E38D83D28F89EF16DFF20153E21E78FB03D4A"
            "E6E39F2BDB83ADF7E93D5A68948140F7F64C261C94692934411520F77602D4F7"
            "BCF46B2ED4A20068D40824713320F46A43B7D4B7500061AF1E39F62E97244546"
            "14214F74BF8B88404D95FC1D96B591AF70F4DDD366A02F45BFBC09EC03BD9785"
            "7FAC6DD031CB850496EB27B355FD3941DA2547E6ABCA0A9A28507825530429F4"
            "0A2C86DAE9B66DFB68DC1462D7486900680EC0A427A18DEE4F3FFEA2E887AD8C"
            "B58CE0067AF4D6B6AACE1E7CD3375FECCE78A399406B2A4220FE9E35D9F385B9"
            "EE39D7AB3B124E8B1DC9FAF74B6D185626A36631EAE397B2E29B0C1C493C69EB"
            "1F9B8B3D8E3D3F1C";

        Byte parsePiHexDigit(char value)
        {
            if (value >= '0' && value <= '9')
            {
                return static_cast<Byte>(value - '0');
            }

            if (value >= 'A' && value <= 'F')
            {
                return static_cast<Byte>(value - 'A' + 10);
            }

            throw std::runtime_error("Blowfish pi hexadecimal digit is invalid");
        }

        std::uint32_t readBigEndian32(const Byte* data)
        {
            return (static_cast<std::uint32_t>(data[0]) << 24u)
                | (static_cast<std::uint32_t>(data[1]) << 16u)
                | (static_cast<std::uint32_t>(data[2]) << 8u)
                | static_cast<std::uint32_t>(data[3]);
        }

        void writeBigEndian32(Byte* output, std::uint32_t value)
        {
            output[0] = static_cast<Byte>((value >> 24u) & 0xFFu);
            output[1] = static_cast<Byte>((value >> 16u) & 0xFFu);
            output[2] = static_cast<Byte>((value >> 8u) & 0xFFu);
            output[3] = static_cast<Byte>(value & 0xFFu);
        }

        std::uint32_t piWord(std::size_t wordIndex)
        {
            const std::size_t offset = wordIndex * 8;

            if (offset + 8 > PiHexDigits.size())
            {
                throw std::runtime_error("Blowfish pi hexadecimal table is too short");
            }

            std::uint32_t value = 0;

            for (std::size_t index = 0; index < 8; ++index)
            {
                value = (value << 4u) | parsePiHexDigit(PiHexDigits[offset + index]);
            }

            return value;
        }

        InitialSubkeys buildInitialSubkeys()
        {
            InitialSubkeys subkeys;
            std::size_t wordIndex = 0;

            for (std::uint32_t& item : subkeys.p)
            {
                item = piWord(wordIndex++);
            }

            for (auto& box : subkeys.s)
            {
                for (std::uint32_t& item : box)
                {
                    item = piWord(wordIndex++);
                }
            }

            if (subkeys.p[0] != 0x243F6A88u
                || subkeys.p[1] != 0x85A308D3u
                || subkeys.s[0][0] != 0xD1310BA6u)
            {
                throw std::runtime_error("Blowfish initial subkey generation failed");
            }

            return subkeys;
        }

        const InitialSubkeys& initialSubkeys()
        {
            static const InitialSubkeys subkeys = buildInitialSubkeys();
            return subkeys;
        }
    }

    Blowfish::Blowfish(std::span<const Byte> key)
    {
        if (key.size() < MinKeySize || key.size() > MaxKeySize)
        {
            throw std::runtime_error("Blowfish key size must be from 4 to 56 bytes");
        }

        const InitialSubkeys& subkeys = initialSubkeys();
        p_ = subkeys.p;
        s_ = subkeys.s;

        std::size_t keyIndex = 0;

        for (std::uint32_t& item : p_)
        {
            std::uint32_t keyWord = 0;

            for (int byteIndex = 0; byteIndex < 4; ++byteIndex)
            {
                keyWord = (keyWord << 8u) | key[keyIndex];
                keyIndex = (keyIndex + 1) % key.size();
            }

            item ^= keyWord;
        }

        std::uint32_t left = 0;
        std::uint32_t right = 0;

        for (std::size_t index = 0; index < p_.size(); index += 2)
        {
            encryptWords(left, right);
            p_[index] = left;
            p_[index + 1] = right;
        }

        for (auto& box : s_)
        {
            for (std::size_t index = 0; index < box.size(); index += 2)
            {
                encryptWords(left, right);
                box[index] = left;
                box[index + 1] = right;
            }
        }
    }

    void Blowfish::encryptBlock(std::array<Byte, BlockSize>& block) const
    {
        std::uint32_t left = readBigEndian32(block.data());
        std::uint32_t right = readBigEndian32(block.data() + 4);

        encryptWords(left, right);

        writeBigEndian32(block.data(), left);
        writeBigEndian32(block.data() + 4, right);
    }

    void Blowfish::decryptBlock(std::array<Byte, BlockSize>& block) const
    {
        std::uint32_t left = readBigEndian32(block.data());
        std::uint32_t right = readBigEndian32(block.data() + 4);

        decryptWords(left, right);

        writeBigEndian32(block.data(), left);
        writeBigEndian32(block.data() + 4, right);
    }

    void Blowfish::selfTest()
    {
        const std::array<Byte, 8> key = {};
        std::array<Byte, BlockSize> block = {};
        const std::array<Byte, BlockSize> expected = {
            0x4Eu, 0xF9u, 0x97u, 0x45u, 0x61u, 0x98u, 0xDDu, 0x78u
        };

        Blowfish blowfish(key);
        blowfish.encryptBlock(block);

        if (block != expected)
        {
            throw std::runtime_error("Blowfish self-test failed");
        }
    }

    std::uint32_t Blowfish::f(std::uint32_t value) const
    {
        const Byte a = static_cast<Byte>((value >> 24u) & 0xFFu);
        const Byte b = static_cast<Byte>((value >> 16u) & 0xFFu);
        const Byte c = static_cast<Byte>((value >> 8u) & 0xFFu);
        const Byte d = static_cast<Byte>(value & 0xFFu);

        return ((s_[0][a] + s_[1][b]) ^ s_[2][c]) + s_[3][d];
    }

    void Blowfish::encryptWords(std::uint32_t& left, std::uint32_t& right) const
    {
        for (std::size_t round = 0; round < 16; ++round)
        {
            left ^= p_[round];
            right ^= f(left);
            std::swap(left, right);
        }

        std::swap(left, right);
        right ^= p_[16];
        left ^= p_[17];
    }

    void Blowfish::decryptWords(std::uint32_t& left, std::uint32_t& right) const
    {
        for (std::size_t round = 17; round > 1; --round)
        {
            left ^= p_[round];
            right ^= f(left);
            std::swap(left, right);
        }

        std::swap(left, right);
        right ^= p_[1];
        left ^= p_[0];
    }
}