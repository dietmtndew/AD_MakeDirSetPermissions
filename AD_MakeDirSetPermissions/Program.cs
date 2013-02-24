using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.AccountManagement;
using System.IO;
using System.Security.AccessControl;
using System.Management;

namespace AD
{
    class Program
    {
        static void Main(string[] args)
        {
            string groupName = "suryarugs";
            string domainName = "suryarugs.local";

            PrincipalContext principleContxt = new PrincipalContext(ContextType.Domain, domainName); 
            GroupPrincipal grpPrincipal = GroupPrincipal.FindByIdentity(principleContxt, IdentityType.SamAccountName, groupName);                 

            if (grpPrincipal != null)
            {
                foreach (Principal p in grpPrincipal.GetMembers(false))
                {
                    if (dont.IndexOf(p.SamAccountName) < 0)
                    {
                        string userPath = @"\\srns1\private\" + p.SamAccountName.ToLower();
                        if (!Directory.Exists(userPath))
                        {
                            Console.ForegroundColor = ConsoleColor.Green;
                            Directory.CreateDirectory(userPath);
                            Console.WriteLine("Directory Created for " + p.SamAccountName);
                        }
                        else
                        {
                            Console.ForegroundColor = ConsoleColor.Magenta;
                            Console.WriteLine("Directory already exists for " + p.SamAccountName);
                        }                        
                        
                        setPermissions(userPath, "IT", FileSystemRights.FullControl, AccessControlType.Allow);
                        setPermissions(userPath, "Domain Admins", FileSystemRights.FullControl, AccessControlType.Allow);
                        setPermissions(userPath, p.SamAccountName, FileSystemRights.Modify, AccessControlType.Allow);                        
                    }                                 
                }
                grpPrincipal.Dispose();
                principleContxt.Dispose();
            }
            else
            {
                Console.WriteLine("Nope");
            }
            Console.WriteLine("\r\nDone. Press enter to exit.");
            Console.ReadLine();
        }

        public static void setPermissions(string path, string user, FileSystemRights userRights, AccessControlType accessType)
        {
            DirectoryInfo dInfo = new DirectoryInfo(path);

            DirectorySecurity dSecurity = dInfo.GetAccessControl();

            dSecurity.AddAccessRule(new FileSystemAccessRule(user, userRights, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.NoPropagateInherit, accessType));

            dSecurity.SetAccessRuleProtection(true, false);
            dInfo.SetAccessControl(dSecurity); 
        }
        public static void RemoveFileSecurity(string fileName, string account,
            FileSystemRights rights, AccessControlType controlType)
        {
            // Get a FileSecurity object that represents the 
            // current security settings.
            FileSecurity fSecurity = File.GetAccessControl(fileName);

            // Remove the FileSystemAccessRule from the security settings.
            fSecurity.RemoveAccessRule(new FileSystemAccessRule(account,
                rights, controlType));

            // Set the new access settings.
            File.SetAccessControl(fileName, fSecurity);
        }
        static List<string> dont = new List<string>()
        {
            //"000conferenceroom",
            //"111MainConferenceRoo",
            //"alerts",
            //"carriers",
            //"admin",
            //"atsadmin",
            //"blytheco",
            //"bizhub",
            //"coptix",
            //"Administrator",
            //"customer",
            //"fedex",
            //"ftpover",
            //"ftpuser",
            //"jobs",
            //"installonly",
            //"krbtgt",
            //"mas200",
            //"payments",
            //"pd1",
            //"pd2",
            //"sage",
            //"SBS Backup User",
            //"SBS User",
            //"SBSMonAcct",
            //"ship1",
            //"sonicwall",
            //"svc_sql",  
            //"1C210FE6-E480-4037-B",
            //"IUSR_DELL-J7OQSA23OW",
            //"IWAM_DELL-J7OQSA23OW",
            //"SM_10feefe212264f26a",
            //"SM_15aab1f6d2334d0fa",
            //"SM_435aa65b31534faca",
            //"SUPPORT_388945a0",
            //"si.yim2",
            //"WebWorkplaceTools",
            //"test.ticket",
            //"test3",
            //"user17",
            //"User Tmpl",
            //"surya",
            //"src",
            //"suryacorp",
            //"webform",
            //"xserve",
            //"Administrator Tmpl",
            //"besadmin",
            //"Mobile User Tmpl",
            //"Network Admin",
            //"spfarm",
            //"spwebapp",
            //"spsearch",
            //"Power User Tmpl",
            //"social",
            //"Standard User",

        };
    }
}

