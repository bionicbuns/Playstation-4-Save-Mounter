using System;
using System.Collections.Generic;
using System.Text;

namespace PS4Saves
{
    class offsets
    {
		//libSceUserService
        public static uint sceUserServiceGetInitialUser = 0;
        public static uint sceUserServiceGetLoginUserIdList = 0;
        public static uint sceUserServiceGetUserName = 0;
        //libSceSaveData
        public static uint sceSaveDataMount = 0;
        public static uint sceSaveDataUmount = 0;
        public static uint sceSaveDataDirNameSearch = 0;
        public static uint sceSaveDataInitialize3 = 0;
    }
}