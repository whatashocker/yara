rule mz
{
	meta:
		description="Is the file a MZ"
	strings:
		$mz = { 4d 5a }
		$dos_message = "!This program cannot be run in DOS mode."
	condition:
		all of them
}
