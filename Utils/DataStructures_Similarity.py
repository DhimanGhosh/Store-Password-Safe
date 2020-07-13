class DS_Similarity:
    def __init__(self, ds1, ds2):
        self.__ds1 = ds1
        self.__ds2 = ds2

    def ds_sim(self):
        if type(self.__ds1).__name__ == type(self.__ds2).__name__:
            if isinstance(self.__ds1, list) or isinstance(self.__ds1, tuple):
                return self.__list_sim(self.__ds1, self.__ds2)
            elif isinstance(self.__ds1, set):
                return self.__ds1 == self.__ds2
            elif isinstance(self.__ds1, dict):
                return self.__dict_sim(self.__ds1, self.__ds2)
            else:
                if self.__ds1 == self.__ds2:
                    return True
        return False

    def __val_chk(self, val1, val2): # Helper Function
        if isinstance(val1, list) or isinstance(val2, tuple):
            if not self.__list_sim(list(val1), list(val2)):
                return False
        elif isinstance(val1, dict):
            if not self.__dict_sim(val1, val2):
                return False
        elif val1 != val2:
            return False
        return True

    def __list_sim(self, list1, list2):
        flag = True
        list1.sort()
        list2.sort()
        if len(list1) == len(list2):
            for i in range(len(list1)):
                if type(list1[i]).__name__ == type(list2[i]).__name__:
                    flag = self.__val_chk(list1[i], list2[i])
                    if not flag:
                        break
                else:
                    flag = False
                    break
        else:
            flag = False
        return flag

    def __dict_sim(self, dict1, dict2):
        flag = True
        if set(dict1.keys()) == set(dict2.keys()):
            for key in dict1.keys():
                if type(dict1[key]).__name__ == type(dict2[key]).__name__:
                    flag = self.__val_chk(dict1[key], dict2[key])
                    if not flag:
                        break
                else:
                    flag = False
                    break
        else:
            flag = False
        return flag
