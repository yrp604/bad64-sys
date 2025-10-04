#pragma once

#include <QDialog>
#include <QStringList>
#include <QLineEdit>
#include <QTreeView>
#include <QPlainTextEdit>
#include <QLabel>
#include <QDialogButtonBox>
#include <QModelIndex>

#include "binaryninjaapi.h"
#include "uitypes.h"

#include <vector>


class ContainerTreeModel : public QAbstractItemModel
{
	Q_OBJECT

public:
	enum Columns { ColName, ColType, ColSize, ColPath, ColCount };

	explicit ContainerTreeModel(TransformSessionRef session, QObject* parent = nullptr);

	// QAbstractItemModel interface
	int columnCount(const QModelIndex& parent = {}) const override;
	QModelIndex index(int row, int column, const QModelIndex& parent = {}) const override;
	QModelIndex parent(const QModelIndex& child) const override;
	int rowCount(const QModelIndex& parent = {}) const override;
	QVariant data(const QModelIndex& index, int role) const override;
	QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
	Qt::ItemFlags flags(const QModelIndex& index) const override;

	// Public helpers for the dialog
	bool isLeaf(const QModelIndex& index) const;
	QStringList pathFor(const QModelIndex& index) const;
	void selectNode(const QModelIndex& index);
	void rebuild();

private:
	struct Node
	{
		QString displayName;          // GetFileName() (or synthesized for root)
		QString type;                 // GetTransformName() or "Leaf"/"Root"
		QString breadcrumb;           // human-readable path "a ▸ b ▸ c"
		QStringList pathSegments;     // list of filenames from root to this node
		quint64 size = 0;             // not exposed (kept for future metadata)
		bool isLeaf = false;
		bool selectable = true;      // we allow selection only on leaves
		TransformContextRef ctx;
		Node* parent = nullptr;
		std::vector<std::unique_ptr<Node>> children;
	};

	const Node* nodeFromIndex(const QModelIndex& index) const;
	static QString joinBreadcrumb(const QStringList& segments);
	void buildChildren(Node* parentNode, const TransformContextRef& ctx, const QStringList& parentSegments);

	TransformSessionRef m_session;
	std::unique_ptr<Node> m_root;
};


class AllColumnsFilterProxyModel : public QSortFilterProxyModel
{
	Q_OBJECT

public:
	explicit AllColumnsFilterProxyModel(QObject* parent = nullptr);

protected:
	bool filterAcceptsRow(int sourceRow, const QModelIndex& sourceParent) const override;
};


class BINARYNINJAUIAPI ContainerBrowser : public QDialog
{
	Q_OBJECT

	TransformSessionRef m_session;

	ContainerTreeModel* m_model;

	QLineEdit* m_filter = nullptr;
	QTreeView* m_tree = nullptr;
	QPlainTextEdit* m_preview = nullptr;
	QLabel* m_status = nullptr;
	QDialogButtonBox* m_buttons = nullptr;
	AllColumnsFilterProxyModel* m_proxy = nullptr;

	QStringList m_selectedPaths;

	void connectSignals();
	void loadRoot();
	void updatePreviewForIndex(const QModelIndex& proxyIndex);
	static QString toHexDump(const QByteArray& data, int bytesPerLine = 16);

public:
	ContainerBrowser(TransformSessionRef session, QWidget* parent = nullptr);

	QStringList selectedPaths() const { return m_selectedPaths; }

	static std::vector<TransformContextRef> openContainerFile(const QString& path);
};
