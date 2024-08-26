{-# LANGUAGE OverloadedStrings #-}

import Crypto.Cipher.AES (AES192)
import Crypto.Cipher.Types (cipherInit, ctrCombine)
import Crypto.Error (CryptoFailable(..))
import Data.ByteArray (convert)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as B

encryptAES192 :: ByteString -> ByteString -> ByteString -> ByteString
encryptAES192 key iv plaintext =
    case cipherInit key of
        CryptoFailed err    -> error (show err)
        CryptoPassed cipher -> ctrCombine cipher iv plaintext

main :: IO ()
main = do
    let plaintext = "This is a secret message."
        iv = "1234567890123456"  -- 16 bytes IV for AES
        key192 = "0123456789abcdef01234567"  -- 24 bytes key

    putStrLn "AES 192-bit Encryption:"
    let ciphertext192 = encryptAES192 key192 iv plaintext
    print (convert ciphertext192 :: ByteString)
