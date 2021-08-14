rule mz
{
	meta:
		description="Is the file a MZ"
	strings:
		$mz_magic = {4D 5A}
		$dos_message = "!This program cannot be run in DOS mode."
	condition:
		all of them
}
