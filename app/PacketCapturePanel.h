#pragma once
#ifdef _DEBUG
#pragma comment(lib,"Debug\\pcaplib.lib")
#else
#pragma comment(lib,"Release\\pcaplib.lib")
#endif 

#include <wx/wx.h>
#include <wx/grid.h>
#include <wx/panel.h>
#include <wx/textctrl.h>
#include <wx/listbox.h>
#include <thread>
#include <atomic>
#include <vector>
#include <string>
#include "pcaplib.h"

class PacketCapturePanel : public wxPanel {
public:
    PacketCapturePanel(wxWindow* parent,const string& dev);
    ~PacketCapturePanel();

    void SaveLogToFile(const wxString& filePath);
    void setSelectedDevice(const string& selectedDevice);
private:
    void OnBackButtonClicked(wxCommandEvent& event);
    void InitUI();

    void BindEvents();

    void OnStartCapture(wxCommandEvent& event);

    void OnStopCapture(wxCommandEvent& event);

    void StopCapture();

    void capturePackets();

    void OnPacketDoubleClick(wxGridEvent& event);

    void OnFilterButtonClick(wxCommandEvent& event);

    void AdjustColumnWidths();

private:
   /* wxBitmapButton* startButton;
    wxBitmapButton* stopButton;*/
    wxButton* startButton; //ĸ�� ���� ��ư
    wxButton* stopButton;  //ĸ�� ���� ��ư
    wxTextCtrl* packetLog; //��Ŷ ������ ȭ��
    wxGrid* packetGrid;// ��Ŷ ���̺�
    wxTextCtrl* filterTextCtrl;//���� text
    wxButton* filterButton; //���� ��ư
    //wxTextCtrl* rawPacketDisplay;
    //wxTextCtrl* detailedLogDisplay;
    int selection = -1;

    std::unique_ptr<PacketCapture> capture;
    std::atomic<bool> isCapturing;
    std::thread captureThread;
    
    std::vector<std::string> capturedPacketDetails;
    
    std::string selectedDevice;
};
