{-# LANGUAGE OverloadedStrings #-}

import Crypto.Cipher.AES (AES128)
import Crypto.Cipher.Types (cipherInit, ctrCombine)
import Crypto.Error (CryptoFailable(..))
import Data.ByteArray (convert)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as B

encryptAES128 :: ByteString -> ByteString -> ByteString -> ByteString
encryptAES128 key iv plaintext =
    case cipherInit key of
        CryptoFailed err    -> error (show err)
        CryptoPassed cipher -> ctrCombine cipher iv plaintext

main :: IO ()
main = do
    let plaintext = "This is a secret message."
        iv = "1234567890123456"  -- 16 bytes IV for AES
        key128 = "0123456789abcdef"  -- 16 bytes key

    putStrLn "AES 128-bit Encryption:"
    let ciphertext128 = encryptAES128 key128 iv plaintext
    print (convert ciphertext128 :: ByteString)
