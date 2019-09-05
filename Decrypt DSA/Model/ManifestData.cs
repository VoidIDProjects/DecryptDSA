using System.Collections.Generic;
using Newtonsoft.Json;

namespace Decrypt_DSA.Model
{
    public class ManifestData
    {
        [JsonProperty("entries")]
        public List<ManifestEntryData> Entries { get; set; }
    }
}
