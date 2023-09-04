using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Solution {
    
    /*
     * The GeminiClient is a very simple implementation of https://gemini.circumlunar.space/docs/specification.gmi
     * This is accomplished by opening a TCP connection at port 1965 to a gemini url and read the response. 
     */
    class GeminiClient {
        
        static void Main(string[] args) {
            Console.WriteLine("==========================\nWelcome to TheGreatGemini\n==========================");
            // new GeminiClient().Request("gemini://gemini.circumlunar.space");
            // new GeminiClient().Request("gemini://gemini.techrights.org/");
            new GeminiClient().Request("gemini://midnight.pub");
        }
        
        /*
         * Request prepares a tcp client with the provided url and port and request an encoded message,
         * It then proceeds to sends the message to be decoded and segmented and finally proceeds to postprocess it.
         */
        public void Request(string url) {
            var (host, page) = PrepareLink(url);
            var client = new TcpClient(host, 1965);
            using (var sslStream = new SslStream(client.GetStream(), false, ValidateCertificate!, null)) {
                sslStream.AuthenticateAsClient(host);
                byte[] bytes = Encoding.UTF8.GetBytes($"gemini://{host}{page}\r\n");
                sslStream.Write(bytes);
                string responseData = DecodeResponse(sslStream);
                var lines = responseData.Split('\n');
                Response(lines);
            }
        }
        
        /*
         * Response determine if any errors are found or format is valid of decoded message and proceeds display is possible.
         */
        private void Response(string[] responseLines) {
            var metadata = responseLines[0].Split(' ');
            var (responseCode, otherInfo) = (metadata[0], metadata[1]);

            if (!otherInfo.StartsWith("text/gemini") && responseCode[0] != '3') {
                throw new ArgumentException("[ERROR] text/gemini is only supported");
            }

            switch (responseCode[0]) {
                case '2':
                    DisplayContent(responseLines);
                    break;
                case '3':
                    Request(otherInfo);
                    break;
                case '4':
                    Console.WriteLine("[Error] temp failure");
                    break;
                case '5':
                    Console.WriteLine("[Error] permanent failure");
                    break;
                default:
                    throw new ArgumentException("[CRITICAL] unknown response code");
            }
        }

        /*
         * DisplayContent outputs array of lines to console
         */
        private void DisplayContent(string[] lines) {
            for (var i = 1; i < lines.Length; i++) {
                Console.WriteLine(lines[i]);
            }
        }
        
        /*
         * PrepareLink preprocesses the provided url to extract certain fields
         * Returns a tuple containing the server and child pages
         */
        private (string, string) PrepareLink(string url) {
            if (url.StartsWith("gemini://")) {
                var curatedUrl = url.Trim().Substring(9);
                int slashIndex = curatedUrl.IndexOf('/'); // first slash
                var parent = (slashIndex == -1) ? curatedUrl : curatedUrl.Remove(slashIndex);
                var child = (slashIndex == -1) ? "/" : curatedUrl.Substring(slashIndex, curatedUrl.Length - slashIndex);
                return (parent, child);
            }
            throw new ArgumentException("URL format not found.");
        }
        
        /*
         * DecodeResponse iterates throughout the SslStream and decodes its
         * Returns a decoded string 
         */
        private string DecodeResponse(SslStream sslStream)
        {
            int bytes;
            byte[] buffer = new byte[2048];
            var data = new StringBuilder();
            do {
                var decoder = Encoding.UTF8.GetDecoder();
                bytes = sslStream.Read(buffer, 0, buffer.Length);
                char[] ch = new char[decoder.GetCharCount(buffer, 0, bytes)];
                decoder.GetChars(buffer, 0, bytes, ch, 0);
                data.Append(ch);
            } while (bytes != 0);
            return data.ToString();
        }
        
        /*
         * ValidateCertificate ensures the elements in the chain matches the found certificate
         * Return a boolean of the result
         */
        private bool ValidateCertificate(object sender, X509Certificate certificate,
            X509Chain chain, SslPolicyErrors sslPolicyErrors) {
            byte[] foundCert = chain.ChainElements[0].Certificate.RawData;
            X509ChainElementCollection elements = chain.ChainElements;
            return elements[elements.Count - 1].Certificate.RawData.SequenceEqual(foundCert);
        }
    }
}