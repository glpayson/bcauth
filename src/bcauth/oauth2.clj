(ns bcauth.oauth2
  (:require
   [clj-jwt.core  :refer :all]
   [clj-jwt.key   :refer [private-key]]
   [clj-time.core :refer [now plus minutes]]
   [clj-http.client :as client]
   [cheshire.core :refer :all]))

(defn parse-token [resp]
  (-> (:body resp)
      (parse-string true)
      (:access_token)))

(defn claim [url cid sig]
  {:iss cid
   :sub cid
   :aud url
   :exp (plus (now) (minutes 30))})

(defn signed-claim [url cid sig]
  (-> (claim url cid sig) 
      jwt 
      (sign :HS512 sig) 
      to-str))

(defn form-params [url cid sig]
  {:form-params
   {:grant_type "client_credentials"
    :client_assertion_type "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    :client_assertion (signed-claim url cid sig)
    :client_id cid}})

(defn get-token [url cid sig]
  (->> (form-params url cid sig)
       (client/post url)
       (parse-token)))
