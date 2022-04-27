$j = Start-Process -FilePath python -ArgumentList "-m", "pyrsecurechannel", "--config=test1.conf" -NoNewWindow  -PassThru
Start-Sleep -Seconds 10
$p = Start-Process -FilePath python -ArgumentList "-m", "pyrloopclient", "--host=localhost", "--port=8002" -NoNewWindow -Wait -PassThru
if ($p.ExitCode -ne 0) {
	throw "FAIL"
}
$p = Start-Process -FilePath python -ArgumentList "-m", "pyrloopclient", "--host=localhost", "--port=8012" -NoNewWindow -Wait -PassThru
if ($p.ExitCode -ne 0) {
	throw "FAIL"
}
Stop-Process -InputObject $j
