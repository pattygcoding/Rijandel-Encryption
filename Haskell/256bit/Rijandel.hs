{-# LANGUAGE OverloadedStrings #-}

import Crypto.Cipher.AES (AES256)
import Crypto.Cipher.Types (cipherInit, ctrCombine)
import Crypto.Error (CryptoFailable(..))
import Data.ByteArray (convert)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as B

encryptAES256 :: ByteString -> ByteString -> ByteString -> ByteString
encryptAES256 key iv plaintext =
    case cipherInit key of
        CryptoFailed err    -> error (show err)
        CryptoPassed cipher -> ctrCombine cipher iv plaintext

main :: IO ()
main = do
    let plaintext = "This is a secret message."
        iv = "1234567890123456"  -- 16 bytes IV for AES
        key256 = "0123456789abcdef0123456789abcdef"  -- 32 bytes key

    putStrLn "AES 256-bit Encryption:"
    let ciphertext256 = encryptAES256 key256 iv plaintext
    print (convert ciphertext256 :: ByteString)
