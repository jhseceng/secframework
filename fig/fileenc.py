##fileEnc.py
##python3.7
##Work@Crowdstrike

#fileEnc.py will encode streaming credentials for the CID
#as well as decode them

import pickle
import os
from simplecrypt import encrypt, decrypt

class fileEnc():
    def __init__(self, logger):
        self.k = 'gB2MW9):F:e[Y)#n'
        self.logger = logger

    def get(self):
        try:

            import config
            self.KEY = config.KEY
            self.UUID = config.UUID
            self.APP_ID = "FIG-SH" + config.APP_ID
            self.PRIORITY = config.PRIORITY
            self.group = [encrypt(self.k, self.KEY), encrypt(self.k, self.UUID), encrypt(self.k, self.APP_ID), encrypt(self.k, self.PRIORITY)]
            self.logger.errorWrite("Got config data".format(self.KEY))
            with open('enc.pickle', 'wb') as handle:
                pickle.dump(self.group, handle, protocol=pickle.HIGHEST_PROTOCOL)
            os.remove('config.py')
            return [self.KEY, self.UUID, self.APP_ID, self.PRIORITY]
        except Exception as error:
            self.logger.errorWrite(error)
            self.logger.errorWrite("Exception reading config.py".format(error))
            try:
                with open('enc.pickle', 'rb') as handle:
                    group = pickle.load(handle)
                    for x in range(0,len(group)):
                        group[x] = decrypt(self.k, group[x])
                        group[x] = group[x].decode("utf-8")
                    return group
            except Exception as e:
                self.logger.errorWrite("Error, no encoded or config file found. Please make a new config.py".format(e))
                os._exit(0)
