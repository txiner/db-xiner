 
import ujson 

stream=open('./result.json','rb')
for line in stream:
                    # print "Line: %s" % line
                    try:
                        data = ujson.loads(line)
                    except Exception as e:
                        print "Exception decoding record (skipping): %s %s" % (e, line)
                    else:
                    	pass
                        #if preprocess:
                         #   preprocess(data)
                    newpdata = str(data.get('filetag', ''))