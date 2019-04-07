using System;
using System.Net;

namespace DotNet40TLSThumbprintPinning
{
	internal class Program
	{
		public static void Main(string[] args)
		{
			new DownloadingShowcase().UseDownloadManager();
			Console.WriteLine("Done");
			Console.ReadLine();
		}
	}

	internal class DownloadingShowcase
	{
		private readonly DownloadManager _downloadManager = new DownloadManager();

		public void UseDownloadManager()
		{
			// Add a sample download to perform
			_downloadManager.AddRequest(new HttpDownloadRequest("ExampleDownload.zip",
				() => (HttpWebRequest) WebRequest.Create("https://github.com/Jofairden/DotNet40TLSThumbprintPinning/releases/download/1.0/ExampleDownload.zip"),
				() => { Console.WriteLine("I finished downloading ExampleDownload.zip!"); }));

			_downloadManager.DownloadFilesFromQueue();
		}
	}
}
