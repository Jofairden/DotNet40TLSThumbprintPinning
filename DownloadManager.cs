using System;
using System.Collections.Generic;
using System.IO;
using System.Net;

namespace DotNet40TLSThumbprintPinning
{
	internal class DownloadManager
	{
		private readonly Queue<DownloadRequest> _requestQueue = new Queue<DownloadRequest>();

		// Very simple KeepAlive logic, we want to use it if we have more than 1 request
		internal bool ShouldUseKeepalive => _requestQueue.Count > 1;

		public void AddRequest(DownloadRequest req)
		{
			_requestQueue.Enqueue(req);
		}

		public void ClearDownloads()
		{
			_requestQueue.Clear();
		}

		public void DownloadFilesFromQueue()
		{
			while (_requestQueue.Count > 0)
			{
				var req = _requestQueue.Peek();
				req.SetupRequest();

				if (req is HttpDownloadRequest httpReq)
				{
					try
					{
						httpReq.Request.KeepAlive = ShouldUseKeepalive;

						Console.WriteLine($"Starting HTTP download request to {httpReq.Request.RequestUri}");
						var response = (HttpWebResponse) httpReq.Request.GetResponse();
						using (var stream = response.GetResponseStream())
						using (var fw = File.OpenWrite($"{Environment.CurrentDirectory}\\{req.Filename}"))
						{
							stream?.CopyTo(fw);
						}

						httpReq.OnFinishCallback();
					}
					catch (Exception e)
					{
						Console.WriteLine(e.ToString());
					}
				}

				_requestQueue.Dequeue();
			}
		}
	}
}