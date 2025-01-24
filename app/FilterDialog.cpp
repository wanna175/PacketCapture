#include "FilterDialog.h"

inline FilterDialog::FilterDialog(wxWindow* parent) : wxDialog(parent, wxID_ANY, "필터 설정", wxDefaultPosition, wxSize(400, 200)) {
    wxBoxSizer* mainSizer = new wxBoxSizer(wxVERTICAL);
    SetBackgroundColour(wxColour(240, 240, 240)); // 밝은 회색 배경

    // 필터 입력 필드 (모던한 스타일)
    wxStaticText* label = new wxStaticText(this, wxID_ANY, "필터 입력 (예: IP, 포트):");
    label->SetForegroundColour(wxColour(50, 50, 50));

    filterInput = new wxTextCtrl(this, wxID_ANY, "", wxDefaultPosition, wxDefaultSize,
        wxBORDER_SIMPLE); // 간소화된 테두리
    filterInput->SetBackgroundColour(wxColour(255, 255, 255));
    filterInput->SetForegroundColour(wxColour(0, 0, 0));

    mainSizer->Add(label, 0, wxLEFT | wxRIGHT | wxTOP, 15);
    mainSizer->Add(filterInput, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 15);

    // 현대적인 버튼 디자인
    wxBoxSizer* buttonSizer = new wxBoxSizer(wxHORIZONTAL);
    wxButton* okButton = new wxButton(this, wxID_OK, "적용", wxDefaultPosition, wxDefaultSize, wxBORDER_NONE);
    wxButton* cancelButton = new wxButton(this, wxID_CANCEL, "취소", wxDefaultPosition, wxDefaultSize, wxBORDER_NONE);

    // 버튼 색상 및 스타일 개선
    okButton->SetBackgroundColour(wxColour(52, 152, 219)); // 파란색
    okButton->SetForegroundColour(*wxWHITE);
    cancelButton->SetBackgroundColour(wxColour(231, 76, 60)); // 빨간색
    cancelButton->SetForegroundColour(*wxWHITE);

    buttonSizer->Add(okButton, 1, wxEXPAND | wxALL, 5);
    buttonSizer->Add(cancelButton, 1, wxEXPAND | wxALL, 5);

    mainSizer->Add(buttonSizer, 0, wxALIGN_CENTER);

    SetSizerAndFit(mainSizer);
}

inline wxString FilterDialog::GetFilter() const {
    return filterInput->GetValue();
}
