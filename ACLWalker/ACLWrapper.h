#pragma once

#include <qstring.h>
#include <QDebug>
#include <QObject>
#include <QList>
#include <QStringList>

#include <Windows.h>
#include <AccCtrl.h>
#include <AclAPI.h>

#pragma comment(lib, "advapi32.lib")



struct Ace_Obj
{
	QString OType;
	QString Domain;
	QString Username;
	QStringList Authorizations;
};


struct AclObject
{
	QString OwnerDomain;
	QString OwnerUsername;
	QList<Ace_Obj> AceObjs;

};






class ACLWrapper : public QObject
{

	Q_OBJECT

public:
	ACLWrapper();
	~ACLWrapper();

	QString GetObjectOwner(QString Path);
	void ProcessPath(QString path);


signals:
	void GetObjectInfo(AclObject * obj);

};

