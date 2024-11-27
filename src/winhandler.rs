use windows::core::{ PCWSTR, HSTRING };
use windows::Win32::Foundation::GENERIC_ALL;
use windows::Win32::Foundation::{ HANDLE, WIN32_ERROR, CloseHandle,
    GENERIC_READ,
    GENERIC_ACCESS_RIGHTS,
    BOOL
};
use windows::Win32::System::SystemServices::ACCESS_SYSTEM_SECURITY;
use windows::Win32::Storage::FileSystem::CreateFileW;
use windows::Win32::Storage::FileSystem::{
    FILE_SHARE_READ,
    OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL,
};
use windows::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION;
use windows::Win32::Security::{
    PSID,
    PSECURITY_DESCRIPTOR,
    SECURITY_DESCRIPTOR,
    SACL_SECURITY_INFORMATION,
    ATTRIBUTE_SECURITY_INFORMATION,
    SECURITY_ATTRIBUTES,
    ACL_REVISION,
    ACL_REVISION_DS,
    ACL,
    InitializeSecurityDescriptor,
    AddAuditAccessAce,
    InitializeAcl,
    INHERITED_ACE,
    AddAuditAccessObjectAce,
    ACE_REVISION,
    GetSecurityDescriptorSacl,
    GetSecurityDescriptorDacl,
    IsValidAcl,
    GetAce,
    SYSTEM_AUDIT_ACE,
    ACE_HEADER
};
use windows::Win32::Security::Authorization::{
    GetSecurityInfo,
    SetSecurityInfo,
    ConvertStringSidToSidW,
    SE_FILE_OBJECT
};
use windows::Win32::System::Threading::OpenProcessToken;
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY, TOKEN_PRIVILEGES,
    SE_PRIVILEGE_ENABLED, SE_SECURITY_NAME
};
use windows::Win32::System::Threading::GetCurrentProcess;
use std::mem::zeroed;

// ----------------------------------------------------------------------------

pub unsafe fn enable_privilege() {
    // Open process token
    let mut token_handle: HANDLE = HANDLE::default();
    match OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token_handle) {
        Ok(_v) => {
            let mut tp = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [zeroed()],
            };

            // Lookup the privilege value
            match LookupPrivilegeValueW(None, SE_SECURITY_NAME, &mut tp.Privileges[0].Luid) {
                Ok(_v) => {
                    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

                    // Adjust token privileges
                    match AdjustTokenPrivileges(token_handle, false, Some(&mut tp), std::mem::size_of::<TOKEN_PRIVILEGES>() as u32, None, None) {
                        Ok(_v) => println!("SeSecurityPrivilege enabled successfully."),
                        Err(e) => println!("Failed to enable SeSecurityPrivilege. {:?}", e)
                    }
                }
                Err(e) => println!("Error on LookupPrivilegeValueW: {:?}", e)
            }
            let _ = CloseHandle(token_handle);
        }
        Err(e) => println!("Error on OpenProcessToken: {:?}", e)
    }
}

// ----------------------------------------------------------------------------

pub unsafe fn get_handle(path: HSTRING) -> HANDLE {
    let security_attr: SECURITY_ATTRIBUTES = SECURITY_ATTRIBUTES::default();
    CreateFileW(
        PCWSTR::from_raw(path.as_ptr()),
        (GENERIC_READ | GENERIC_ACCESS_RIGHTS(ACCESS_SYSTEM_SECURITY)).0,
        FILE_SHARE_READ,
        Some(&security_attr),
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        None
    ).unwrap()
}

// ----------------------------------------------------------------------------

pub unsafe fn get_sacl_security_info(handle: HANDLE) -> ACL {
    // Get current security descriptor
    let mut psecurity_descriptor: PSECURITY_DESCRIPTOR =
        PSECURITY_DESCRIPTOR::default();
    let ptr_mut: *mut *mut ACL = &mut std::ptr::null_mut();


    //println!("ACL mut pointer: {:?}", ptr_mut);
    //println!("Getting mut pointer info: {:?}", *ptr_mut);
    //println!("PSecurity Descriptor: {:?}", psecurity_descriptor);
    //println!("ptr ACL : {:?}", *ptr_mut);
    println!();
    println!("Getting Security Info...");
    let result = GetSecurityInfo(
        handle,
        SE_FILE_OBJECT,
        SACL_SECURITY_INFORMATION | ATTRIBUTE_SECURITY_INFORMATION,
        None,
        None,
        None,
        Some(ptr_mut),
        Some(&mut psecurity_descriptor),
    );
    if result != WIN32_ERROR(0) {
        println!("Failed to get security info: {:?}", result);
    } else {
        println!("Security Info obtained!");
        let sec_desc = psecurity_descriptor.0 as *mut SECURITY_DESCRIPTOR;
        println!("Security Descriptor: {:?}", *sec_desc);
        println!();
    }

    let mut acl: ACL = **ptr_mut;
    //acl.AceCount = 1;
    //acl.AclSize = 64000;
    println!("SD -> ACL: {:?}", acl);
    println!("SD -> ACL valid: {:?}", IsValidAcl(&acl));
    use std::ffi::c_void;
    println!("Getting ACEs...");
    for n in 0..acl.AceCount {
        let mut pace: *mut c_void = std::ptr::null_mut();
        GetAce(&acl, n as u32, &mut pace);
        let ace_header: *mut ACE_HEADER = pace as *mut ACE_HEADER;
        println!("{:?}", *ace_header);
    }
    println!();
/*
    let mut aclc = ACL::default();
    InitializeAcl(&mut aclc, 64, ACL_REVISION_DS);
    println!("SD -> ACLC valid: {:?}", IsValidAcl(&aclc));
    println!("ACLC: {:?}", aclc);
    println!("Getting ACEs...");
    for n in 0..aclc.AceCount {
        let mut pace: *mut c_void = std::ptr::null_mut();
        GetAce(&aclc, n as u32, &mut pace);
        let ace: *mut SYSTEM_AUDIT_ACE = pace as *mut SYSTEM_AUDIT_ACE;
        println!("ACE: {:?}", *ace);
    }
    println!();*/

    if *ptr_mut != std::ptr::null_mut() {
        println!("The ACL contains previous information.");
        println!("ACL info: {:?}", **ptr_mut);
        println!();
        **ptr_mut
    } else {
        ACL::default()
    }

}

// ----------------------------------------------------------------------------

pub unsafe fn add_security_ace(mut acl: *mut ACL, sid: PSID) {
    // Add audit access ACEs for the desired events
    println!("Adding Audit Access Ace");
    match AddAuditAccessObjectAce(
        acl,
        ACE_REVISION((*acl).AclRevision as u32),
        INHERITED_ACE,
        GENERIC_ALL.0,
        None,
        None,
        sid,
        true,
        true){
            Ok(_v) => println!("Added Audit Access Ace."),
            Err(e) => println!("Error adding Audit Ace, {:?}", e)
    };
}

// ----------------------------------------------------------------------------

pub unsafe fn set_security_info(handle: HANDLE, mut acl: *mut ACL) {
    // Set the new SACL in the security descriptor
    let result = SetSecurityInfo(handle, SE_FILE_OBJECT, SACL_SECURITY_INFORMATION,
        None, None, None, Some(acl as *mut _ as *mut _),
    );
    if result != WIN32_ERROR(0) {
        println!("Failed to set security info: {:?}", result);
        return;
    } else {
        println!("Security info set!")
    }
}