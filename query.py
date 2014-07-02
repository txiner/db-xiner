

select(i.token, min(i.time), where=((i.campaign_io_id == 17146) |(i.campaign_io_id == 17147) |(i.campaign_io_id == 17160)) & (i.impressions > 0) & (i.is_psa == 0) & (i.date == '2014-02-20'), nest=True)

pcappacket=Table.create('pcappacket',columns=['int32 GMTtime','int32 MicroTime','int32 caplen','int32 len','index string ethtype','index string protocol','uint8 ttl','index uint8 sip0','index uint8 sip1','index uint8 sip2','index uint8 sip3','index uint8 dip0','index uint8 dip1','index uint8 dip2','index uint8 dip3','index int16 sport','index int16 dport','string data'],partition=None,force=True)
insert(pcappacket,'./bin/result.json',server='disco://hustle')
pretreatment('/home/xiner/hustle/pcapread/testall.pcap')
