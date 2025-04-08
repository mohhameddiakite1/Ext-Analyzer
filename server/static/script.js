document.addEventListener("DOMContentLoaded", () => {
  //to colorize risk score on page load
  colorizeRiskScore();

  const tab = document.querySelectorAll(".tab-btn");
  const tabContents = document.querySelectorAll(".tab-content");

  tab.forEach((button) => {
    button.addEventListener("click", () => {
      //Remove active class from all buttons and contents
      tab.forEach((btn) => btn.classList.remove("active"));
      tabContents.forEach((content) => content.classList.remove("active"));

      //Add active class to current button
      button.classList.add("active");

      //Show corresponding content
      const tabId = button.getAttribute("data-tab");
      document.getElementById(`${tabId}-tab`).classList.add("active");

      // Colorize the risk score
      colorizeRiskScore();

      if (button.getAttribute("data-tab") === "report") {
        buildReportSection();
      }
    });
  });

  // Export buttons
  document
    .getElementById("export-pdf")
    ?.addEventListener("click", generatePdfReport);
  document
    .getElementById("export-json")
    ?.addEventListener("click", generateJsonReport);

  // permissions editing
  editPermissionsSection();

  // Recommendations management
  manageRecommendations();

  // Build report section

  buildReportSection();
});

function generatePdfReport() {
  const { jsPDF } = window.jspdf;
  const doc = new jsPDF();
  const date = new Date().toLocaleDateString();
  const pageWidth = doc.internal.pageSize.width;
  let yPosition = 20;
  const lineHeight = 7;
  const margin = 20;

  // Helper function for text wrapping
  function addText(text, y, fontSize = 11) {
    doc.setFontSize(fontSize);
    const lines = doc.splitTextToSize(text, pageWidth - 2 * margin);
    doc.text(lines, margin, y);
    return y + lines.length * lineHeight;
  }

  // Helper function for section headers
  function addHeader(text, y) {
    doc.setFontSize(14);
    doc.setFont(undefined, "bold");
    doc.text(text, margin, y);
    doc.setFont(undefined, "normal");
    doc.setFontSize(11);
    return y + 10;
  }

  // Check if we need a new page
  function checkPage(y, needed = 20) {
    if (y + needed > doc.internal.pageSize.height - 20) {
      doc.addPage();
      return 20;
    }
    return y;
  }

  // Title
  doc.setFontSize(16);
  doc.setFont(undefined, "bold");
  yPosition = addText("Extension Analysis Report", yPosition, 16);
  doc.setFont(undefined, "normal");
  yPosition += 5;
  yPosition = addText(`Generated on ${date}`, yPosition);
  yPosition += 10;

  // Summary Section
  yPosition = addHeader("Summary", yPosition);

  // Get all summary content
  const summaryContent = [
    {
      label: "Extension Name",
      value:
        document.querySelector("#extension-name-value")?.textContent.trim() ||
        "N/A",
    },
    {
      label: "Risk Score",
      value: document.querySelector("#risk-score")?.textContent.trim() || "N/A",
    },
    {
      label: "Hash",
      value:
        document
          .querySelector("#hash-code")
          ?.textContent.replace("(SHA256):", "")
          .trim() || "N/A",
    },
    {
      label: "Referenced URLs",
      value:
        document
          .querySelector("#ref-urls-num")
          ?.textContent.replace("Referenced URLs", "")
          .trim() || "N/A",
    },
    {
      label: "Permissions",
      value:
        document
          .querySelector("#perms-num")
          ?.textContent.replace("Permissions", "")
          .trim() || "N/A",
    },
  ];

  // Add basic info compactly
  let summaryText = summaryContent
    .map((item) => `${item.label}: ${item.value}`)
    .join("\n");

  // Add malicious content compactly
  let maliciousScripts =
    document
      .querySelector("#malicious-scripts")
      ?.textContent.replace(/\s+/g, " ")
      .replace(
        "Potentially Malicious Scripts:",
        "Potentially Malicious Scripts:\n"
      )
      .trim() || "N/A";

  let maliciousManifest =
    document
      .querySelector("#malicious-manifest-fields")
      ?.textContent.replace(/\s+/g, " ")
      .replace(
        "Potentially Malicious Manifest Fields:",
        "Potentially Malicious Manifest Fields:\n"
      )
      .trim() || "N/A";

  // Combine all summary content
  summaryText += `\n${maliciousScripts}\n${maliciousManifest}`;

  // Calculate box size and draw
  const summaryLines = doc.splitTextToSize(
    summaryText,
    pageWidth - 2 * margin - 10
  );
  const boxHeight = summaryLines.length * lineHeight + 6;

  doc.setDrawColor(150, 150, 150);
  doc.rect(margin, yPosition, pageWidth - 2 * margin, boxHeight);
  yPosition += 3;

  // Add all content in one go
  yPosition = addText(summaryText, yPosition);
  yPosition += 15;

  // Permissions Section

  //Build permission entries
  const permissionEntries = [];
  let permissionReportEntry = ``;
  let permissionsText = "";
  yPosition += 10;
  yPosition = checkPage(yPosition, 30);
  yPosition = addHeader("Permission Analysis", yPosition);
  const permissions = document.querySelectorAll(".permission-item");
  permissions.forEach((permission) => {
    const permissionName = permission
      .querySelector(".permission-name")
      .childNodes[0].textContent.trim();
    const permissionText = permission
      .querySelector(".permission-text")
      .textContent.trim();
    const riskSelect = permission.querySelector(".risk-select");
    const riskLevel = riskSelect ? riskSelect.value.toUpperCase() : "";

    permissionReportEntry = `- ${permissionName} [${riskLevel}]\n${permissionText}`;
    permissionEntries.push(permissionReportEntry);
  });
  // Add entries to the pdf report
  permissionEntries.forEach((entry) => {
    if (entry.trim()) {
      yPosition = checkPage(yPosition, 40);

      // Draw a simple box around each permission
      const lines = doc.splitTextToSize(
        entry.trim(),
        pageWidth - 2 * margin - 10
      );
      const boxHeight = lines.length * lineHeight + 6;
      doc.setDrawColor(200, 200, 200);
      doc.rect(margin, yPosition - 3, pageWidth - 2 * margin, boxHeight);

      // Add permission text
      yPosition = addText(entry.trim(), yPosition);
      yPosition += 15;
    }
  });

  // Recommendations Section
  yPosition = checkPage(yPosition, 30);
  yPosition = addHeader("Security Recommendations", yPosition);
  const recommendationsEntries = [];
  const recommendations = document.querySelectorAll(".recommendation-item");

  if (recommendations.length > 0) {
    recommendations.forEach((recommendation, index) => {
      const text = recommendation
        .querySelector(".recommendation-description")
        .textContent.trim();
      // Split long text into smaller chunks with proper line breaks
      const lines = doc.splitTextToSize(text, pageWidth - 2 * margin - 10);
      recommendationReportEntry = `${index + 1}. ${lines.join("")}`;
      recommendationsEntries.push(recommendationReportEntry);
    });
  } else {
    recommendationReportEntry = "No specific recommendations.";
    recommendationsEntries.push(recommendationReportEntry);
  }

  recommendationsEntries.forEach((rec) => {
    if (rec.trim()) {
      yPosition = checkPage(yPosition, 20);
      yPosition = addText(rec.trim(), yPosition);
      yPosition += 5; // Reduced spacing between recommendations
    }
  });

  // Add page numbers
  const totalPages = doc.internal.getNumberOfPages();
  for (let i = 1; i <= totalPages; i++) {
    doc.setPage(i);
    doc.setFontSize(10);
    doc.text(
      `Page ${i} of ${totalPages}`,
      pageWidth / 2,
      doc.internal.pageSize.height - 10,
      { align: "center" }
    );
  }

  // Save the PDF
  doc.save(`extension-analysis-${date.replace(/\//g, "-")}.pdf`);
}

// Generate and download JSON report
function generateJsonReport() {
  const date = new Date().toLocaleDateString();

  // Get extension basic info
  const extName =
    document.querySelector("#extension-name-value")?.textContent.trim() ||
    "N/A";
  const riskScore =
    document.querySelector("#risk-score")?.textContent.trim() || "N/A";
  const hashCode =
    document.querySelector("#hash-code")?.textContent.trim() || "N/A";
  const maliciousScripts =
    document.querySelector("#malicious-scripts")?.textContent.trim() || "N/A";
  const refUrlsNum =
    document.querySelector("#ref-urls-num")?.textContent.trim() || "N/A";
  const permsNum =
    document.querySelector("#perms-num")?.textContent.trim() || "N/A";

  // Build permissions entries
  const permissionEntries = [];
  document.querySelectorAll(".permission-item").forEach((permission) => {
    const permissionName = permission
      .querySelector(".permission-name")
      .childNodes[0].textContent.trim();
    const permissionText = permission
      .querySelector(".permission-text")
      .textContent.trim();
    const riskSelect = permission.querySelector(".risk-select");
    const riskLevel = riskSelect ? riskSelect.value.toUpperCase() : "";

    permissionEntries.push({
      permission: permissionName,
      risk_level: riskLevel,
      description: permissionText,
    });
  });

  // Build recommendations entries
  const recommendationsEntries = [];
  document
    .querySelectorAll(".recommendation-item")
    .forEach((recommendation) => {
      const text = recommendation
        .querySelector(".recommendation-description")
        .textContent.trim();
      recommendationsEntries.push(text);
    });

  // Make JSON structure
  const reportData = {
    generated_on: date,
    extension_info: {
      name: extName,
      risk_score: riskScore,
      hash: hashCode,
      malicious_scripts: maliciousScripts,
      referenced_urls: refUrlsNum,
      permissions_count: permsNum,
    },
    permissions: permissionEntries,
    recommendations: recommendationsEntries.length
      ? recommendationsEntries
      : ["No specific recommendations."],
  };

  // Fortmat and make JSON file downloadable
  const jsonString = JSON.stringify(reportData, null, 2);
  const json_blob = new Blob([jsonString], { type: "application/json" });
  const url = URL.createObjectURL(json_blob); // Temp url to allow download
  const link = document.createElement("a");
  link.href = url;
  link.download = `extension-analysis-${date.replace(/\//g, "-")}.json`;
  link.click();
  URL.revokeObjectURL(url); // clean up
}

function editPermissionsSection() {
  document.querySelectorAll(".risk-select").forEach((select) => {
    const originalRiskScore = select.getAttribute("data-original");
    select.value = originalRiskScore;

    select.addEventListener("change", function () {
      const permissionItem = this.closest(".permission-item");
      permissionItem.classList.remove(
        "none-risk",
        "low-risk",
        "medium-risk",
        "high-risk",
        "critical-risk"
      );
      permissionItem.classList.add(`${this.value}-risk`);
      this.setAttribute("data-original", this.value);
    });
  });

  // Handle edit buttons
  document.querySelectorAll(".edit-btn").forEach((btn) => {
    btn.addEventListener("click", function () {
      const descriptionDiv = this.closest(".permission-description");
      const permissionText = descriptionDiv.querySelector(".permission-text");
      const controls = descriptionDiv.querySelector(".edit-controls");
      const textarea = controls.querySelector(".edit-textarea");

      permissionText.style.display = "none";
      this.style.display = "none";
      controls.classList.remove("hidden");
      textarea.value = text.textContent.trim();
    });
  });

  // Handle save buttons
  document.querySelectorAll(".save-btn").forEach((btn) => {
    btn.addEventListener("click", function () {
      const descriptionDiv = this.closest(".permission-description");
      const permissionText = descriptionDiv.querySelector(".permission-text");
      const controls = descriptionDiv.querySelector(".edit-controls");
      const textarea = controls.querySelector(".edit-textarea");
      const editBtn = descriptionDiv.querySelector(".edit-btn");

      permissionText.textContent = textarea.value;
      permissionText.style.display = "block";
      editBtn.style.display = "block";
      controls.classList.add("hidden");
    });
  });

  // Handle cancel buttons
  document.querySelectorAll(".cancel-btn").forEach((btn) => {
    btn.addEventListener("click", function () {
      const descriptionDiv = this.closest(".permission-description");
      const permissionText = descriptionDiv.querySelector(".permission-text");
      const controls = descriptionDiv.querySelector(".edit-controls");
      const editBtn = descriptionDiv.querySelector(".edit-btn");

      permissionText.style.display = "block";
      editBtn.style.display = "block";
      controls.classList.add("hidden");
    });
  });

  // Handle edit all button
  const editAllBtn = document.querySelector(".edit-all-btn");
  const editControls = document.querySelector(".edit-controls");

  editAllBtn?.addEventListener("click", function () {
    this.classList.add("hidden");
    editControls.classList.remove("hidden");

    // Enable all selects and show all textareas
    document.querySelectorAll(".risk-select").forEach((select) => {
      select.disabled = false;
    });

    document.querySelectorAll(".permission-text").forEach((text) => {
      text.classList.add("hidden");
    });

    document.querySelectorAll(".edit-textarea").forEach((textarea) => {
      textarea.classList.remove("hidden");
    });
  });

  // Handle save all button
  document
    .querySelector(".save-all-btn")
    ?.addEventListener("click", function () {
      // Hide save/cancel buttons
      editControls.classList.add("hidden");
      editAllBtn.classList.remove("hidden");

      // Disable all selects and update text content
      document.querySelectorAll(".risk-select").forEach((select) => {
        select.disabled = true;
        select.setAttribute("data-original", select.value);
      });

      document.querySelectorAll(".permission-description").forEach((desc) => {
        const permissionText = desc.querySelector(".permission-text");
        const textarea = desc.querySelector(".edit-textarea");

        permissionText.textContent = textarea.value;
        permissionText.classList.remove("hidden");
        textarea.classList.add("hidden");
      });

      buildReportSection();
    });

  // Handle cancel all button
  document
    .querySelector(".cancel-all-btn")
    ?.addEventListener("click", function () {
      editControls.classList.add("hidden");
      editAllBtn.classList.remove("hidden");

      // Reset all selects to original values and disable selects
      document.querySelectorAll(".risk-select").forEach((select) => {
        const originalRiskScore = select.getAttribute("data-original");
        select.value = originalRiskScore;
        select.disabled = true;
      });

      // Reset all textareas and add hidden
      document.querySelectorAll(".permission-description").forEach((desc) => {
        const PermissionText = desc.querySelector(".permission-text");
        const textArea = desc.querySelector(".edit-textarea");

        textArea.value = PermissionText.textContent;
        PermissionText.classList.remove("hidden");
        textArea.classList.add("hidden");
      });
    });
}

// Colorize risk score based on value
function colorizeRiskScore() {
  const riskScoreElement = document.getElementById("risk-score");
  if (riskScoreElement) {
    const score = parseInt(riskScoreElement.getAttribute("score-data"));
    riskScoreElement.classList.remove(
      "risk-score-low",
      "risk-score-medium",
      "risk-score-high",
      "risk-score-critical"
    );

    if (score <= 25) {
      riskScoreElement.classList.add("risk-score-low");
    } else if (score <= 50) {
      riskScoreElement.classList.add("risk-score-medium");
    } else if (score <= 75) {
      riskScoreElement.classList.add("risk-score-high");
    } else {
      riskScoreElement.classList.add("risk-score-critical");
    }
  }
}

function manageRecommendations() {
  const recommendationsContainer = document.getElementById("recommendations");
  const addBtn = document.getElementById("add-recommendation");
  let recommendationsNum = document.querySelectorAll(
    ".recommendation-item"
  ).length;

  // Add new recommendation
  addBtn?.addEventListener("click", () => {
    recommendationsNum++;

    const noRecommsText = recommendationsContainer.querySelector(
      ".no-recommendations"
    );
    // Remove "No recommendations" text if it exists
    if (noRecommsText) {
      noRecommsText.classList.add("hidden");
    }

    const newRecommendation = document.createElement("div");
    newRecommendation.className = "recommendation-item";
    newRecommendation.innerHTML = `
      <div class="recommendation-header">
        <div class="recommendation-title">Recommendation ${recommendationsNum}</div>
        <button class="delete-recommendation-btn">&times;</button>
      </div>
      <div class="recommendation-description" contenteditable="true">Enter recommendation here...</div>
    `;

    recommendationsContainer.appendChild(newRecommendation);
    const descriptionDiv = newRecommendation.querySelector(
      ".recommendation-description"
    );
    // descriptionDiv.focus();
    // descriptionDiv.select();

    buildReportSection();
  });

  // Delete recommendation
  recommendationsContainer.addEventListener("click", (e) => {
    if (e.target.classList.contains("delete-recommendation-btn")) {
      const recommendationItem = e.target.closest(".recommendation-item");
      recommendationItem.remove();

      // Update recommendations number
      document
        .querySelectorAll(".recommendation-title")
        .forEach((title, index) => {
          title.textContent = `Recommendation ${index + 1}`;
        });

      recommendationsNum--;

      // Display "No recommendations" text if they a are all deleted
      if (recommendationsNum === 0) {
        noRecommsText.classList.remove("hidden");
      }

      buildReportSection();
    }
  });

  // Listen for changes in recommendation text
  recommendationsContainer.addEventListener("input", (e) => {
    if (e.target.classList.contains("recommendation-description")) {
      buildReportSection();
    }
  });
}

function buildReportSection() {
  const summarySectionInReport = document.getElementById("report-summary");
  const permissionsSectionInReport =
    document.getElementById("report-permissions");
  const recommendationsSectionInReport = document.getElementById(
    "report-recommendations"
  );
  const permissions = document.querySelectorAll(".permission-item");
  let permissionsText = "";
  const recommendations = document.querySelectorAll(".recommendation-item");
  let recommendationsText = "";

  summarySectionInReport.innerHTML = "";
  permissionsSectionInReport.innerHTML = "";
  recommendationsSectionInReport.innerHTML = "";

  // Add summary to the report
  const summaryDiv = document.querySelector(".summary-text");
  const summaryText = Array.from(summaryDiv.children)
    .map((p) => p.textContent.trim())
    .join("<br><br>");
  const riskScore = document.getElementById("risk-score").innerHTML;

  summarySectionInReport.innerHTML = `
    <div class="scrollable-content">
      Risk Score: ${riskScore}<br><br>
      ${summaryText}
    </div>
  `;

  // Add permissions to the report
  permissions.forEach((permission) => {
    const permissionName = permission
      .querySelector(".permission-name")
      .childNodes[0].textContent.trim();
    const permissionText = permission
      .querySelector(".permission-text")
      .textContent.trim();
    const riskSelect = permission.querySelector(".risk-select");
    const riskLevel = riskSelect ? riskSelect.value.toUpperCase() : "";

    permissionsText += `- ${permissionName} [${riskLevel}]<br>${permissionText}<br><br>`;
  });

  permissionsSectionInReport.innerHTML = `<div class="scrollable-content">${permissionsText}</div>`;

  // Add recommendations to the report
  if (recommendations.length > 0) {
    recommendations.forEach((recommendation, index) => {
      const text = recommendation
        .querySelector(".recommendation-description")
        .textContent.trim();
      recommendationsText += `${index + 1}. ${text}<br><br>`;
    });
  } else {
    recommendationsText = "No specific recommendations.";
  }

  recommendationsSectionInReport.innerHTML = `<div class="scrollable-content">${recommendationsText}</div>`;
}
