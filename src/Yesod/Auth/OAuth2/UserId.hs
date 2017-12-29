{-# LANGUAGE OverloadedStrings #-}
module Yesod.Auth.OAuth2.UserId
    ( UserId(..)
    , userIdent
    , UserIdText(..)
    ) where

import Data.Aeson
import Data.Text (Text)
import qualified Data.Text as T

-- | Parse-able type to use for responses with an integer @id@ field
newtype UserId = UserId { userId :: Int }

instance FromJSON UserId where
    parseJSON = withObject "User" $ \o -> UserId <$> o .: "id"

userIdent :: UserId -> Text
userIdent = T.pack . show . userId

-- | Parse-able type to use for responses with a textual @id@ field
newtype UserIdText = UserIdText { userIdentText :: Text }

instance FromJSON UserIdText where
    parseJSON = withObject "User" $ \o -> UserIdText <$> o .: "id"
