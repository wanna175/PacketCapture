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
// 패킷 데이터 구조체 정의
struct PacketData {
    int number;
    string time;
    string source;
    string destination;
    string protocol;
    int length;
    string info;
    string rawData;  // 원본 패킷 데이터
};
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

    void AdjustColumnWidths();

private:
    wxListBox* packetList;
   /* wxBitmapButton* startButton;
    wxBitmapButton* stopButton;*/
    wxButton* startButton;
    wxButton* stopButton;
    wxTextCtrl* packetLog;
    wxGrid* packetGrid;
    wxTextCtrl* rawPacketDisplay;
    wxTextCtrl* detailedLogDisplay;

    std::unique_ptr<PacketCapture> capture;
    std::atomic<bool> isCapturing;
    std::thread captureThread;
    
    std::vector<std::string> capturedPacketDetails;
    
    std::string selectedDevice;
};
