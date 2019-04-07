using System;

namespace DotNet40TLSThumbprintPinning
{
	internal abstract class DownloadRequest
	{
		public readonly string Filename;
		public readonly Action OnFinishCallback;

		protected DownloadRequest(string filename, Action onFinishCallback)
		{
			Filename = filename;
			OnFinishCallback = onFinishCallback;
		}

		public virtual bool SetupRequest() => true;
	}
}