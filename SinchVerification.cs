using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Linq;
using System;
using System.Globalization;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using static System.Net.Mime.MediaTypeNames;

namespace SinchVerificationRequestSigning
{
    public static class SinchVerification
    {
        private const string _timeHeader = "x-timestamp";

        static string GenerateVerificationCode()
        {
            Random random = new Random();
            return random.Next(1000, 9999).ToString();
        }

        private static async Task<string> BuildStringToSignAsync(StringContent requestBody, string timestamp)
        {
            var sb = new StringBuilder();

            sb.Append("POST");
            sb.AppendLine();

            using (var md5 = MD5.Create())
            {
                sb.Append(Convert.ToBase64String(md5.ComputeHash(await requestBody.ReadAsByteArrayAsync().ConfigureAwait(false))));
            }
            sb.AppendLine();

            sb.Append("application/json; charset=utf-8");
            sb.AppendLine();

            sb.Append(_timeHeader);
            sb.Append(":");
            sb.Append(timestamp);
            sb.AppendLine();

            sb.Append("/verification/v1/verifications");

            return sb.ToString();
        }

        private static string GetSignature(byte[] secret, string stringToSign)
        {
            using (var sha = new HMACSHA256(secret))
            {
                return Convert.ToBase64String(
                    sha.ComputeHash(Encoding.UTF8.GetBytes(stringToSign))
                );
            }
        }

        public static StringContent GetSMSVerificationRequestBody()
        {
            var myData = new
            {
                identity = new
                {
                    type = "number",
                    endpoint = "+916290208036"
                },
                method = "sms",
            };

            return new StringContent(
                JsonSerializer.Serialize(myData),
                Encoding.UTF8,
                Application.Json
            );
        }

        [FunctionName("SinchVerification")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            log.LogInformation("SinchVerification HTTP trigger function processed a request.");

            string jsonPhoneNumber = await new StreamReader(req.Body).ReadToEndAsync();
            dynamic data = JObject.Parse(jsonPhoneNumber);

            string phoneNumber = data.phoneNumber;
            string sinchAppKey = Environment.GetEnvironmentVariable("SinchAppKey");
            string sinchAppSecret = Environment.GetEnvironmentVariable("SinchAppSecret");
            string sinchURL = Environment.GetEnvironmentVariable("sinchURL");
            //string base64Auth = Convert.ToBase64String(Encoding.ASCII.GetBytes($@"{sinchAppKey}:{sinchAppSecret}"));
            string authCode = GenerateVerificationCode();

            using (var _client = new HttpClient())
            {

                //var requestJson = JObject.Parse($@"
                //                {{
                //                    ""identity"": {{
                //                        ""type"": ""number"",
                //                        ""endpoint"": ""{phoneNumber}""
                //                    }},
                //                    ""method"": ""sms"",
                //                    ""smsOptions"": {{
                //                        ""expiry"": ""00:01:00"",
                //                        ""codeType"": ""Numeric"",
                //                        ""code"":""{authCode}"",
                //                        ""template"": ""this is abhishek.please find the {{{{CODE}}}}""
                //                 }}
                //                }}");
                var requestBody = GetSMSVerificationRequestBody();
                var timestamp = DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture);

                //var requestBody = new StringContent(requestJson.ToString(), Encoding.UTF8, "application/json");
                var stringToSign = await BuildStringToSignAsync(requestBody, timestamp);
                var b64decodedApplicationSecret = Convert.FromBase64String(sinchAppSecret);

                var authAuthAppValue = sinchAppKey + ":" + GetSignature(b64decodedApplicationSecret, stringToSign);

                var requestMessage = new HttpRequestMessage(HttpMethod.Post, sinchURL);
                requestMessage.Headers.TryAddWithoutValidation("authorization", "application " + authAuthAppValue);
                requestMessage.Headers.Add(_timeHeader, timestamp);
                //_client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("application", authAuthAppValue);
                //_client.DefaultRequestHeaders.Add(_timeHeader, timestamp);

                requestMessage.Content = requestBody;

                var response = await _client.SendAsync(requestMessage);
                //var response = await _client.PostAsync("https://verification.api.sinch.com/verification/v1/verifications", requestBody);
                //request.EnsureSuccessStatusCode();
                var responseContent = await response.Content.ReadAsStringAsync();
                dynamic responseData = JObject.Parse(responseContent);
                log.LogError($"Response Content:{responseContent} ");
                if (!response.IsSuccessStatusCode)
                {
                    log.LogError($"SinchVerification API request failed with status code {response.StatusCode}");
                    return new StatusCodeResult(StatusCodes.Status500InternalServerError);
                }

                //var responseContent = await response.Content.ReadAsStringAsync();
                //dynamic responseData = JObject.Parse(responseContent);
                //log.LogError($"Response Content:{responseContent} ");
            }

            var responseBody = new JObject
            {
                { "phoneNumber", phoneNumber },
                { "pinCode", authCode }
            };

            return new OkObjectResult(responseBody);
        }
    }
}
