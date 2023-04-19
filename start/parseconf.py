import os
import configparser

from .singleton import Singleton


class Configuration(metaclass=Singleton):

    def __init__(self, cfgFile):
        self.cfgFile = cfgFile


    def readConf(self):
        conf = configparser.RawConfigParser()
        _path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), self.cfgFile
                )
        conf.read(_path)
        self.config = conf
        return conf

    def changeConf(self, *args):
        # print ("changeConf")
        conf = configparser.RawConfigParser()
        _path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), self.cfgFile
                )
        conf.read(_path)
        self.config = conf
        self.args = args[0]

    
        list_windows10 = self.config.items('Windows 10')
        list_windows11 = self.config.items('Windows 11')
        list_windows7 = self.config.items('Windows 7')

        list_Syscalls = self.config.items('SYSCALLS')
        list_Misc = self.config.items('MISC')


        # sharem_search = self.config.items('SHAREM SEARCH')
        # sharem_syscalls = self.config.items('SHAREM SYSCALLS')
        # sharem_decoder = self.config.items('SHAREM DECRYPT')
        # sharem_emulation = self.config.items('SHAREM EMULATION')
        # sharem_disassembly = self.config.items('SHAREM DISASSEMBLY')

        for key, val in self.args.items():
            for x in list_windows10:
                if(key in x):
                    self.config['Windows 10'][str(key)] = str(val)
                    # print(self.config['Windows 10'][str(key)],str(val))
        
        for key, val in self.args.items():
            for x in list_windows7:
                if(key in x):
                    self.config['Windows 7'][str(key)] = str(val)
           
        for key, val in self.args.items():
            for x in list_windows11:
                if(key in x):
                    self.config['Windows 11'][str(key)] = str(val)
           
        for key, val in self.args.items():
            for x in list_Syscalls:
                if(key in x):
                    self.config['SYSCALLS'][str(key)] = str(val)

        for key, val in self.args.items():
            for x in list_Misc:
                if(key in x):
                    self.config['MISC'][str(key)] = str(val)
           
            # print("Key: ", key, "Val: ", val)
            # print(vars(self.config))


        # if "pushret" in self.args:
        #     self.config['SHAREM SEARCH']['pushret'] = str(self.args['pushret'])
     



        #save = self.save() 
    def save(self):
        # print("saving")
        _path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), self.cfgFile
                )
        with open(_path, "w") as configfile:
            self.config.write(configfile)
            # print(configfile)
        # print("done")
