{-# LANGUAGE OverloadedStrings #-}
module Yesod.Auth.OAuth2.EveOnline
    ( oauth2EveOnline
    ) where

import Data.Aeson
import qualified Data.Text as T
import Yesod.Auth.OAuth2.Provider

newtype CharId = CharId { charId :: Int }

instance FromJSON CharId where
    parseJSON = withObject "Character" $ \o -> CharId <$> o .: "CharacterId"

oauth2EveOnline :: ClientId -> ClientSecret -> [Scope] -> Provider m CharId
oauth2EveOnline cid cs scopes = Provider
    { pName = "eveonline"
    , pClientId = cid
    , pClientSecret = cs
    , pAuthorizeEndpoint = AuthorizeEndpoint
        $ "https://login.eveonline.com/oauth/authorize" `withQuery`
            [ ("response_type", "code")
            , scopeParam " " scopes
            ]
    , pAccessTokenEndpoint = "https://login.eveonline.com/oauth/token"
    , pFetchUserProfile = authGetProfile "https://login.eveonline.com/oauth/verify"
    , pParseUserProfile = eitherDecode
    , pUserProfileToIdent = T.pack . show . charId
    }
