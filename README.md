**#AutomatedRDS**<br>

**disclaimer** *Current code comes from 2017 and it left much to be desired, never the less back then it did the trick, for quick lab deployment. Similar things can be achieved with GUI, or other products available here and there, but still back then when was creating this it was a bit of challenge for me. As of now (2022.02) there is plan to rewrite it, and add a module for the automation on top of the RDS itself, which brings missing RDS tooling, with the use of PS and it's convinience. It's just not consolidated and shared here yet.*<br><br>
**#Unatended installation of Remote Desktop Services**<br>
 PowerShell script which installs the Remote Desktop Services 2016 in unatended way<br>
 
 test conditions:<br>
 - Windows Server 2016<br>
 - WMF5.1<br>

 it should work on:<br>
 - Windows Server 2012R2<br>
 - WMF5<br>

 has not been tested on:<br>
 - Windows Server 2012<br>
 - WMF4<br>

 all variables are stored in psd1 files<br>
 
 this is a rewritten version of https://github.com/citrixguyblog/PowerShellRDSDeployment<br>
 
 **#Places worth to follow for the RDS automation context**<br>
 + https://mehic.se/category/remote-desktop-services-2016/<br>

![rds2016_multi_deployment](https://user-images.githubusercontent.com/28138611/153015202-af021a46-dfe8-4d5e-a5bd-99538c622fc9.gif)
