using System;
using System.Text;
using Newtonsoft.Json;

namespace Decrypt_DSA.Model
{
    public class SteamGuardData
    {
        private string _phoneNumber;


        [JsonProperty("account_name")]
        public string AccountName { get; set; }

        [JsonProperty("steam_id")]
        public ulong SteamID { get; set; }

        [JsonProperty("device_id")]
        public string DeviceID { get; set; }

        [JsonProperty("phone_number")]
        public string PhoneNumber
        {
            get => _phoneNumber;
            set
            {
                StringBuilder temp = new StringBuilder(value);
                temp.Replace("-", "").Replace("(", "").Replace(")", "");
                if (temp == null || temp.Length == 0) _phoneNumber = String.Empty;
                if (temp[0] != '+') _phoneNumber = String.Empty;
                _phoneNumber = temp.ToString();
            }
        }

        [JsonProperty("shared_secret")]
        public string SharedSecret { get; set; }

        [JsonProperty("serial_number")]
        public string SerialNumber { get; set; }

        [JsonProperty("revocation_code")]
        public string RevocationCode { get; set; }

        [JsonProperty("uri")]
        public string URI { get; set; }

        [JsonProperty("server_time")]
        public long ServerTime { get; set; }

        [JsonProperty("token_gid")]
        public string TokenGID { get; set; }

        [JsonProperty("identity_secret")]
        public string IdentitySecret { get; set; }

        [JsonProperty("secret_1")]
        public string Secret1 { get; set; }

        [JsonProperty("status")]
        public int Status { get; set; }

        [JsonProperty("fully_enrolled")]
        public bool FullyEnrolled { get; set; }
    }
}
