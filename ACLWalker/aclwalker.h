#ifndef ACLWALKER_H
#define ACLWALKER_H

#include <QtWidgets/QMainWindow>
#include <qfilesystemmodel.h>
#include "ui_aclwalker.h"

#include "ACLWrapper.h"


class ACLWalker : public QMainWindow
{
	Q_OBJECT

public:
	ACLWalker(QWidget *parent = 0);
	~ACLWalker();

private:
	Ui::ACLWalkerClass ui;
	QFileSystemModel *m_dirModel;
	QFileSystemModel *m_filesModel;

	ACLWrapper * m_aclWrapper;


public slots:
	void on_treeView_bro_dirs_clicked(QModelIndex index);
	void on_treeView_bro_files_clicked(QModelIndex index);
	void on_retrieveAcl(AclObject * aclObj);

};

#endif // ACLWALKER_H
