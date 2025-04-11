// run in powerquery:
event.category = "process"
tgt.process.name matches ("taskkill\\.exe")
| let time_bucket =timebucket("5m") 
| group taskkill_count_5m = count(tgt.process.name), commandline_list=hacklist(tgt.process.cmdline), oldest_time_unix=oldest(event.time), parent_process=any(src.process.name), parent_cmdline=any(src.process.cmdline) by endpoint.name, time_bucket
| filter taskkill_count_5m > 10
| columns endpoint.name, taskkill_count_5m, commandline_list, parent_process, parent_cmdline, oldest_time_unix

TgtProcCmdLine ContainsCIS "--remote-debugging-port" AND TgtProcCmdLine ContainsCIS "--remote-allow-origins"

// run in powerquery:
event.category = "file"
endpoint.name = tgt.file.internalName 
| columns event.time, endpoint.name, tgt.file.internalName, src.process.user, src.process.name, tgt.file.path

Sha256 In AnyCase ("8d1b6a215e194bda4130a11c9e5111341f6b97428d3c1606a6dda67602b62384", "ac0f02d78b3864df71c6a2529d98da15dd421ea4bcf2d0f1773fc35c7a16caa8", "923c26cd40e7e046f38ad5455a2becf5c9694ad371fc34d593f249adb5f2fb6c", "940c1e6daaf12c293b55c56d02d06c237fa6cf6e30cb643c1a6a8ddc25210428", "533958e064d091b0fa8f31e7fe254380b5449552ecf24c4c94bf7fb8ae1ce327", "d5d6383b49f2156b2327e8aadefc7a5558697afd94ea3d52db2a34808eeede06")

DnsRequest In AnyCase ("malenugame.blogspot.com", "malenugames.blogspot.com","supremeserve.discloud.app")