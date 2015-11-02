#include "aclwalker.h"

ACLWalker::ACLWalker(QWidget *parent)
	: QMainWindow(parent)
{
	ui.setupUi(this);
	ACLWalker::setCentralWidget(NULL);

	m_aclWrapper = new ACLWrapper();

	QString sRootPath = "C:/";
	m_dirModel = new QFileSystemModel(this);
	m_dirModel->setRootPath(sRootPath);
	m_dirModel->setFilter(QDir::NoDotAndDotDot | QDir::AllDirs);
	ui.treeView_bro_dirs->setModel(m_dirModel);

	m_filesModel = new QFileSystemModel(this);
	m_filesModel->setFilter(QDir::NoDotAndDotDot | QDir::Files);
	m_filesModel->setRootPath(sRootPath);
	ui.treeView_bro_files->setModel(m_filesModel);

	connect(ui.treeView_bro_dirs, SIGNAL(clicked(QModelIndex)), this, SLOT(on_treeView_bro_dirs_clicked(QModelIndex)));
	connect(m_aclWrapper, SIGNAL(GetObjectInfo(AclObject*)), this, SLOT(on_retrieveAcl(AclObject*)));

	
}

ACLWalker::~ACLWalker()
{

}


void ACLWalker::on_treeView_bro_dirs_clicked(QModelIndex index)
{
	QString sPath = m_dirModel->fileInfo(index).absoluteFilePath();
	ui.treeView_bro_files->setRootIndex(m_filesModel->setRootPath(sPath));
	m_aclWrapper->ProcessPath(sPath);
}

void ACLWalker::on_treeView_bro_files_clicked(QModelIndex index)
{
	QString sPath = m_filesModel->fileInfo(index).absoluteFilePath();
	m_aclWrapper->ProcessPath(sPath);
}

void ACLWalker::on_retrieveAcl(AclObject * aclObj)
{

	ui.treeWidget->clear();

	qDebug() << aclObj->OwnerUsername;
	ui.lineEdit->setText(aclObj->OwnerDomain + "/" + aclObj->OwnerUsername);

	for (int i = 0; i < aclObj->AceObjs.count(); i++)
	{
		QTreeWidgetItem * item = new QTreeWidgetItem();
		item->setText(0, aclObj->AceObjs.at(i).Domain + "/" + aclObj->AceObjs.at(i).Username);
		
		for (size_t ii = 0; ii < aclObj->AceObjs.at(i).Authorizations.count(); ii++)
		{
			QTreeWidgetItem *subItem = new QTreeWidgetItem();
			subItem->setText(0, aclObj->AceObjs.at(i).Authorizations.at(ii));
			if (aclObj->AceObjs.at(i).OType == "ACCESS_ALLOWED_ACE_TYPE")
			{
				subItem->setText(1, "X");
			}
			else
			{
				subItem->setText(2, "X");
			}
			item->addChild(subItem);
		}
		ui.treeWidget->addTopLevelItem(item);
	}

	ui.treeView_bro_dirs->resizeColumnToContents(0);

}

