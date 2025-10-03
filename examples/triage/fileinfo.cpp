#include "fileinfo.h"
#include "fontsettings.h"
#include "theme.h"
#include "copyablelabel.h"
#include <QClipboard>
#include <QApplication>
#include <QToolTip>
#include <QPainter>
#include <QtConcurrent/QtConcurrent>
#include <QFuture>
#include <QFutureWatcher>

void FileInfoWidget::addCopyableField(const QString& name, const QVariant& value)
{
	auto& [row, column] = this->m_fieldPosition;

	const auto valueLabel = new CopyableLabel(value.toString(), getThemeColor(AlphanumericHighlightColor));
	valueLabel->setFont(getMonospaceFont(this));

	this->m_layout->addWidget(new QLabel(name), row, column);
	this->m_layout->addWidget(valueLabel, row++, column + 1);
}

void FileInfoWidget::addField(const QString& name, const QVariant& value)
{
	auto& [row, column] = this->m_fieldPosition;

	const auto valueLabel = new QLabel(value.toString());
	valueLabel->setFont(getMonospaceFont(this));

	this->m_layout->addWidget(new QLabel(name), row, column);
	this->m_layout->addWidget(valueLabel, row++, column + 1);
}

void FileInfoWidget::addHashFields(BinaryViewRef view)
{
	auto& [row, column] = this->m_fieldPosition;

	const auto hashFieldColor = getThemeColor(AlphanumericHighlightColor);
	auto md5Label = new CopyableLabel("Calculating...", hashFieldColor);
	auto sha1Label = new CopyableLabel("Calculating...", hashFieldColor);
	auto sha256Label = new CopyableLabel("Calculating...", hashFieldColor);
	md5Label->setFont(getMonospaceFont(this));
	sha1Label->setFont(getMonospaceFont(this));
	sha256Label->setFont(getMonospaceFont(this));

	this->m_layout->addWidget(new QLabel("MD5: "), row, column);
	this->m_layout->addWidget(md5Label, row++, column + 1);
	this->m_layout->addWidget(new QLabel("SHA-1: "), row, column);
	this->m_layout->addWidget(sha1Label, row++, column + 1);
	this->m_layout->addWidget(new QLabel("SHA-256: "), row, column);
	this->m_layout->addWidget(sha256Label, row++, column + 1);

	// Process the hash calculations in a separate thread and update the labels when done
	QPointer<QFutureWatcher<QStringList>> watcher = new QFutureWatcher<QStringList>(this);
	connect(watcher, &QFutureWatcher<QStringList>::finished, this, [watcher, md5Label, sha1Label, sha256Label]() {
		if (watcher)
		{
			if (const auto results = watcher->result(); results.size() == 3)
			{
				md5Label->setText(results[0]);
				sha1Label->setText(results[1]);
				sha256Label->setText(results[2]);
			}
			watcher->deleteLater();
		}
	});

	uint64_t totalSize = view->GetLength();
	QFuture<QStringList> future = QtConcurrent::run([view, totalSize, watcher]() {
		QCryptographicHash md5(QCryptographicHash::Md5);
		QCryptographicHash sha1(QCryptographicHash::Sha1);
		QCryptographicHash sha256(QCryptographicHash::Sha256);

		uint64_t offset = 0;
		const uint64_t maxChunkSize = 128 * 1024 * 1024;
		auto chunkBuffer = std::make_unique<char[]>(maxChunkSize);
		while (offset < totalSize)
		{
			if (watcher->isCanceled())
				return QStringList();

			const auto remainingBytes = totalSize - offset;
			const auto currentChunkSize = std::min(maxChunkSize, remainingBytes);
			const auto bytesRead = view->Read(chunkBuffer.get(), offset, currentChunkSize);
			if (bytesRead != currentChunkSize)
				return QStringList{"Error", "Error", "Error"};

			const auto chunkView = QByteArrayView(chunkBuffer.get(), currentChunkSize);
			md5.addData(chunkView);
			sha1.addData(chunkView);
			sha256.addData(chunkView);
			offset += currentChunkSize;
		}

		return QStringList {md5.result().toHex(), sha1.result().toHex(), sha256.result().toHex()};
	});

	watcher->setFuture(future);
	connect(this, &QObject::destroyed, this, [watcher]() {
		if (watcher && watcher->isRunning()) {
			watcher->cancel();
			watcher->waitForFinished();
		}
	});
}

FileInfoWidget::FileInfoWidget(QWidget* parent, BinaryViewRef bv)
{
	this->m_layout = new QGridLayout();
	this->m_layout->setContentsMargins(0, 0, 0, 0);
	this->m_layout->setVerticalSpacing(1);

	const auto view = bv->GetParentView() ? bv->GetParentView() : bv;

	const auto file = bv->GetFile();
	const auto filePath = file->GetOriginalFilename();
	this->addCopyableField("Path on disk: ", filePath.c_str());

	// If triage view is opened from a project, show both actual filepath and path relative to project
	if (const auto fileProjectRef = file->GetProjectFile())
	{
		const auto projectFilePath = file->GetProjectFile()->GetPathInProject();
		this->addCopyableField("Path in project: ", projectFilePath.c_str());
	}

	const auto fileSize = QString::number(view->GetLength(), 16).prepend("0x");
	this->addCopyableField("Size: ", fileSize);

	this->addHashFields(view);

	const auto scaledWidth = UIContext::getScaledWindowSize(20, 20).width();
	this->m_layout->setColumnMinimumWidth(FileInfoWidget::m_maxColumns * 3 - 1, scaledWidth);
	this->m_layout->setColumnStretch(FileInfoWidget::m_maxColumns * 3 - 1, 1);
	setLayout(this->m_layout);
}