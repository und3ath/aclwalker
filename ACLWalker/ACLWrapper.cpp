#include "ACLWrapper.h"


ACLWrapper::ACLWrapper()
{
}


ACLWrapper::~ACLWrapper()
{
}

QString ACLWrapper::GetObjectOwner(QString Path)
{
	PSECURITY_DESCRIPTOR pSecDesc = NULL;
	PACL pDacl;
	ACL_SIZE_INFORMATION aclSize = { 0 };
	PSID pSidOwner = NULL;
	PSID pSidGroup = NULL;


	ULONG uResult = GetNamedSecurityInfo(Path.toStdWString().c_str(),
		SE_FILE_OBJECT,
		OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
		&pSidOwner,
		&pSidGroup,
		&pDacl, 
		NULL,
		&pSecDesc);

	if (uResult != ERROR_SUCCESS)
	{
		throw;
	}


	wchar_t *oname = new TCHAR[512];
	DWORD namelen = 0;
	wchar_t *doname = new TCHAR[512];
	DWORD domainenamelen = 0;

	SID_NAME_USE peUse;
	ACCESS_ALLOWED_ACE *ace;

	LookupAccountSid(NULL, pSidOwner, oname, &namelen, doname, &domainenamelen, &peUse);
	qDebug() << "Owner: " << QString::fromWCharArray(doname) << "/" << QString::fromWCharArray(oname) << "\n";

	LookupAccountSid(NULL, pSidGroup, oname, &namelen, doname, &domainenamelen, &peUse);
	qDebug() << "Group: " << QString::fromWCharArray(doname) << "/" << QString::fromWCharArray(oname) << "\n";


	qDebug() << "\n\n\n::DACL::\n";
	SID * sid;
	unsigned long i, mask;
	char *stringSid;

	for (int i = 0; i < (*pDacl).AceCount; i++)
	{
		int c = 1;
		// Get the pointer of the access control entry (ACE) in an access control list (ACL)
		BOOL b = GetAce(pDacl, i, (PVOID*)&ace);

		

		if (((ACCESS_ALLOWED_ACE *)ace)->Header.AceType == ACCESS_ALLOWED_ACE_TYPE)
		{
			sid = (SID*)& ((ACCESS_ALLOWED_ACE *)ace)->SidStart;
			LookupAccountSid(NULL, sid, oname, &namelen, doname, &domainenamelen, &peUse);
			qDebug() << "ACCESS_ALLOWED_ACE SID: " << QString::fromWCharArray(doname) << "/" << QString::fromWCharArray(oname) << "\n";

			mask = ((ACCESS_ALLOWED_ACE *)ace)->Mask;
		}
		else if (((ACCESS_DENIED_ACE *)ace)->Header.AceType == ACCESS_DENIED_ACE_TYPE) 
		{
			sid = (SID *)&((ACCESS_DENIED_ACE *)ace)->SidStart;
			LookupAccountSid(NULL, sid, oname, &namelen, doname, &domainenamelen, &peUse);
			qDebug() << "ACCESS_DENIED_ACE SID: " << QString::fromWCharArray(doname) << "/" << QString::fromWCharArray(oname) << "\n";
			
			mask = ((ACCESS_DENIED_ACE *)ace)->Mask;
		}
		else
		{
			qDebug() << "Other ACE \n";
		}



		qDebug() << "ACE: mask: " 
			<< ace->Mask 
			<< " sidStart:" 
			<< ace->SidStart 
			<< " headerType=" 
			<< ace->Header.AceType 
			<< " headerFlags=" 
			<< ace->Header.AceFlags 
			<< "\n";



	/*	if (DELETE & ace->Mask) {
			qDebug() << " DELETE" << "\n";
			aceObj.Authorizations.append("DELETE");
		}
		if (FILE_GENERIC_READ & ace->Mask) {
			qDebug() << " FILE_GENERIC_READ" << "\n";
			aceObj.Authorizations.append("FILE_GENERIC_READ");
		}
		if (FILE_GENERIC_WRITE & ace->Mask) {
			qDebug() << " FILE_GENERIC_WRITE" << "\n";
			aceObj.Authorizations.append("FILE_GENERIC_WRITE");
		}
		if (FILE_GENERIC_EXECUTE & ace->Mask) {
			qDebug() << " FILE_GENERIC_EXECUTE" << "\n";
			aceObj.Authorizations.append("FILE_GENERIC_EXECUTE");
		}
		if (GENERIC_READ & ace->Mask) {
			qDebug() << " GENERIC_READ" << "\n";
			aceObj.Authorizations.append("GENERIC_READ");
		}
		if (GENERIC_WRITE & ace->Mask) {
			qDebug() << " GENERIC_WRITE" << "\n";
			aceObj.Authorizations.append("GENERIC_WRITE");
		}
		if (GENERIC_EXECUTE & ace->Mask) {
			qDebug() << " GENERIC_EXECUTE" << "\n";
			aceObj.Authorizations.append("GENERIC_EXECUTE");
		}
		if (GENERIC_ALL & ace->Mask) {
			qDebug() << " GENERIC_ALL" << "\n";
			aceObj.Authorizations.append("GENERIC_ALL");
		}
		if (READ_CONTROL & ace->Mask) {
			qDebug() << " READ_CONTROL" << "\n";
			aceObj.Authorizations.append("READ_CONTROL");
		}
		if (WRITE_DAC & ace->Mask) {
			qDebug() << " WRITE_DAC" << "\n";
			aceObj.Authorizations.append("WRITE_DAC");
		}
		if (WRITE_OWNER & ace->Mask) {
			qDebug() << " WRITE_OWNER" << "\n";
			aceObj.Authorizations.append("WRITE_OWNER");
		}
		if (SYNCHRONIZE & ace->Mask) {
			qDebug() << " SYNCHRONIZE" << "\n";
			aceObj.Authorizations.append("SYNCHRONIZE");
		}
		qDebug() << "\n";*/
	}


	SECURITY_DESCRIPTOR* p1 = (SECURITY_DESCRIPTOR*)pSecDesc;

	qDebug() <<  "\n\n\n::SECURITY_DESCRIPTOR_CONTROL::" << "\n";

	SECURITY_DESCRIPTOR_CONTROL ctrl = (*p1).Control;
	if (SE_OWNER_DEFAULTED & ctrl) {
		qDebug() << " SE_OWNER_DEFAULTED" << "\n";
	}
	if (SE_DACL_PRESENT & ctrl) {
		qDebug() << " SE_DACL_PRESENT" << "\n";
	}
	if (SE_DACL_DEFAULTED & ctrl) {
		qDebug() << " SE_DACL_DEFAULTED" << "\n";
	}
	if (SE_SACL_PRESENT & ctrl) {
		qDebug() << " SE_SACL_PRESENT" << "\n";
	}
	if (SE_SACL_DEFAULTED & ctrl) {
		qDebug() << " SE_SACL_DEFAULTED" << "\n";
	}
	if (SE_DACL_AUTO_INHERIT_REQ & ctrl) {
		qDebug() << " SE_DACL_AUTO_INHERIT_REQ" << "\n";
	}
	if (SE_SACL_AUTO_INHERIT_REQ & ctrl) {
		qDebug() << " SE_SACL_AUTO_INHERIT_REQ" << "\n";
	}
	if (SE_SACL_AUTO_INHERITED & ctrl) {
		qDebug() << " SE_SACL_AUTO_INHERITED" << "\n";
	}
	if (SE_DACL_PROTECTED & ctrl) {
		qDebug() << " SE_DACL_PROTECTED" << "\n";
	}
	if (SE_SACL_PROTECTED & ctrl) {
		qDebug() << " SE_SACL_PROTECTED" << "\n";
	}
	if (SE_RM_CONTROL_VALID & ctrl) {
		qDebug() << " SE_RM_CONTROL_VALID" << "\n";
	}
	if (SE_SELF_RELATIVE & ctrl) {
		qDebug() << " SE_SELF_RELATIVE" << "\n";
	}

	LocalFree(pSecDesc);
	LocalFree(pSidOwner);
	LocalFree(pSidGroup);


}

void ACLWrapper::ProcessPath(QString path)
{
	AclObject * aclObj = new AclObject();

	PSECURITY_DESCRIPTOR pSecDesc = NULL;
	PACL pDacl;
	ACL_SIZE_INFORMATION aclSize = { 0 };
	PSID pSidOwner = NULL;
	PSID pSidGroup = NULL;


	ULONG uResult = GetNamedSecurityInfo(path.toStdWString().c_str(),
		SE_FILE_OBJECT,
		OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
		&pSidOwner,
		&pSidGroup,
		&pDacl,
		NULL,
		&pSecDesc);

	if (uResult != ERROR_SUCCESS) {
		throw;
	}

	wchar_t *oname = new TCHAR[512];
	DWORD namelen;
	wchar_t *doname = new TCHAR[512];
	DWORD domainenamelen;

	SID_NAME_USE peUse;
	ACCESS_ALLOWED_ACE *ace;

	LookupAccountSid(NULL, pSidOwner, oname, &namelen, doname, &domainenamelen, &peUse);
	qDebug() << "Owner: " << QString::fromWCharArray(doname) << "/" << QString::fromWCharArray(oname) << "\n";
	if (domainenamelen > 1 && namelen > 1) {
		aclObj->OwnerDomain = QString::fromWCharArray(doname);
		aclObj->OwnerUsername = QString::fromWCharArray(oname);
	}

	LookupAccountSid(NULL, pSidGroup, oname, &namelen, doname, &domainenamelen, &peUse);
	qDebug() << "Group: " << QString::fromWCharArray(doname) << "/" << QString::fromWCharArray(oname) << "\n";


	qDebug() << "\n\n\n::DACL::\n";
	SID * sid;
	unsigned long i, mask;
	char *stringSid;

	for (int i = 0; i < (*pDacl).AceCount; i++)
	{
		int c = 1;
		// Get the pointer of the access control entry (ACE) in an access control list (ACL)
		BOOL b = GetAce(pDacl, i, (PVOID*)&ace);
		Ace_Obj aceObj;

		if (((ACCESS_ALLOWED_ACE *)ace)->Header.AceType == ACCESS_ALLOWED_ACE_TYPE)
		{
			sid = (SID*)& ((ACCESS_ALLOWED_ACE *)ace)->SidStart;
			LookupAccountSid(NULL, sid, oname, &namelen, doname, &domainenamelen, &peUse);
			qDebug() << "ACCESS_ALLOWED_ACE SID: " << QString::fromWCharArray(doname) << "/" << QString::fromWCharArray(oname) << "\n";
			if (namelen > 1 || domainenamelen > 1)
			{
				aceObj.OType = "ACCESS_ALLOWED_ACE_TYPE";
				aceObj.Domain = QString::fromWCharArray(doname);
				aceObj.Username = QString::fromWCharArray(oname);
			}
			mask = ((ACCESS_ALLOWED_ACE *)ace)->Mask;
		}
		else if (((ACCESS_DENIED_ACE *)ace)->Header.AceType == ACCESS_DENIED_ACE_TYPE)
		{
			sid = (SID *)&((ACCESS_DENIED_ACE *)ace)->SidStart;
			LookupAccountSid(NULL, sid, oname, &namelen, doname, &domainenamelen, &peUse);
			qDebug() << "ACCESS_DENIED_ACE SID: " << QString::fromWCharArray(doname) << "/" << QString::fromWCharArray(oname) << "\n";
			if (namelen > 1 || domainenamelen > 1)
			{
				aceObj.OType = "ACCESS_DENIED_ACE_TYPE";
				aceObj.Domain = QString::fromWCharArray(doname);
				aceObj.Username = QString::fromWCharArray(oname);
			}
			mask = ((ACCESS_DENIED_ACE *)ace)->Mask;
		}
		else
		{
			qDebug() << "Other ACE \n";
		}



		qDebug() << "ACE: mask: "
			<< ace->Mask
			<< " sidStart:"
			<< ace->SidStart
			<< " headerType="
			<< ace->Header.AceType
			<< " headerFlags="
			<< ace->Header.AceFlags
			<< "\n";



		if (DELETE & ace->Mask) {
			qDebug() << " DELETE" << "\n";
			aceObj.Authorizations.append("DELETE");
		}
		if (FILE_GENERIC_READ & ace->Mask) {
			qDebug() << " FILE_GENERIC_READ" << "\n";
			aceObj.Authorizations.append("FILE_GENERIC_READ");
		}
		if (FILE_GENERIC_WRITE & ace->Mask) {
			qDebug() << " FILE_GENERIC_WRITE" << "\n";
			aceObj.Authorizations.append("FILE_GENERIC_WRITE");
		}
		if (FILE_GENERIC_EXECUTE & ace->Mask) {
			qDebug() << " FILE_GENERIC_EXECUTE" << "\n";
			aceObj.Authorizations.append("FILE_GENERIC_EXECUTE");
		}
		if (GENERIC_READ & ace->Mask) {
			qDebug() << " GENERIC_READ" << "\n";
			aceObj.Authorizations.append("GENERIC_READ");
		}
		if (GENERIC_WRITE & ace->Mask) {
			qDebug() << " GENERIC_WRITE" << "\n";
			aceObj.Authorizations.append("GENERIC_WRITE");
		}
		if (GENERIC_EXECUTE & ace->Mask) {
			qDebug() << " GENERIC_EXECUTE" << "\n";
			aceObj.Authorizations.append("GENERIC_EXECUTE");
		}
		if (GENERIC_ALL & ace->Mask) {
			qDebug() << " GENERIC_ALL" << "\n";
			aceObj.Authorizations.append("GENERIC_ALL");
		}
		if (READ_CONTROL & ace->Mask) {
			qDebug() << " READ_CONTROL" << "\n";
			aceObj.Authorizations.append("READ_CONTROL");
		}
		if (WRITE_DAC & ace->Mask) {
			qDebug() << " WRITE_DAC" << "\n";
			aceObj.Authorizations.append("WRITE_DAC");
		}
		if (WRITE_OWNER & ace->Mask) {
			qDebug() << " WRITE_OWNER" << "\n";
			aceObj.Authorizations.append("WRITE_OWNER");
		}
		if (SYNCHRONIZE & ace->Mask) {
			qDebug() << " SYNCHRONIZE" << "\n";
			aceObj.Authorizations.append("SYNCHRONIZE");
		}
		qDebug() << "\n";

		aclObj->AceObjs.append(aceObj);

	}

	
	emit GetObjectInfo(aclObj);

}