document.addEventListener("DOMContentLoaded", () => {
  //to colorize risk score on page load
  colorizeRiskScore();

  const tabButtons = document.querySelectorAll(".tab-btn");
  const tabContents = document.querySelectorAll(".tab-content");

  tabButtons.forEach((button) => {
    button.addEventListener("click", () => {
      //Remove active class from all buttons and contents
      tabButtons.forEach((btn) => btn.classList.remove("active"));
      tabContents.forEach((content) => content.classList.remove("active"));

      //Add active class to current button
      button.classList.add("active");

      //Show corresponding content
      const tabId = button.getAttribute("data-tab");
      document.getElementById(`${tabId}-tab`).classList.add("active");

      // Colorize the risk score
      colorizeRiskScore();

      // Update report when switching to report tab
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

// Generate and download PDF report
function generatePdfReport() {
  const { jsPDF } = window.jspdf;
  const doc = new jsPDF();
  const date = new Date().toLocaleDateString();

  // Title
  doc.setFontSize(18);
  doc.text("Extension Analysis Report", 10, 20);
  doc.setFontSize(12);
  doc.text(`Generated on ${date}`, 10, 30);

  // Extension info
  doc.setFontSize(14);
  doc.text("Extension Information", 10, 45);
  doc.setFontSize(12);
  doc.text(
    `Name: ${
      document.getElementById("extension-name-value")?.textContent || "N/A"
    }`,
    10,
    55
  );
  doc.text(
    `Risk Score: ${
      document.getElementById("risk-score")?.textContent || "N/A"
    }`,
    10,
    65
  );

  // Summary
  doc.setFontSize(14);
  doc.text("Summary", 10, 80);
  doc.setFontSize(12);
  doc.text(
    document.getElementById("report-summary")?.textContent ||
      "No summary available",
    10,
    90,
    {
      maxWidth: 180,
    }
  );

  // Permissions
  doc.setFontSize(14);
  doc.text("Permission Analysis", 10, 110);
  doc.setFontSize(12);
  doc.text(
    document.getElementById("report-permissions")?.textContent ||
      "No permissions available",
    10,
    120,
    {
      maxWidth: 180,
    }
  );

  // Recommendations
  doc.setFontSize(14);
  doc.text("Security Recommendations", 10, 140);
  doc.setFontSize(12);
  doc.text(
    document.getElementById("report-recommendations")?.textContent ||
      "No recommendations available",
    10,
    150,
    { maxWidth: 180 }
  );

  // Save the PDF
  doc.save(`extension-analysis-${date}.pdf`);
}

// Generate and download JSON report
function generateJsonReport() {
  const reportData = {
    extensionName:
      document.getElementById("extension-name-value")?.textContent || "N/A",
    riskScore: document.getElementById("risk-score")?.textContent || "N/A",
    summary:
      document.getElementById("report-summary")?.textContent ||
      "No summary available",
    permissionAnalysis:
      document.getElementById("report-permissions")?.textContent ||
      "No permissions available",
    recommendations:
      document.getElementById("report-recommendations")?.textContent ||
      "No recommendations available",
    generatedOn: new Date().toISOString(),
  };

  const jsonBlob = new Blob([JSON.stringify(reportData, null, 2)], {
    type: "application/json",
  });
  const jsonUrl = URL.createObjectURL(jsonBlob);
  const jsonLink = document.createElement("a");
  jsonLink.href = jsonUrl;
  jsonLink.download = `extension-analysis-${new Date()
    .toLocaleDateString()
    .replace(/\//g, "-")}.json`;
  jsonLink.click();
}

// Add this new function
function editPermissionsSection() {
  // Set initial select values
  document.querySelectorAll(".risk-select").forEach((select) => {
    const originalRiskScore = select.getAttribute("data-original");
    select.value = originalRiskScore;

    select.addEventListener("change", function () {
      const permissionItem = this.closest(".permission-item");
      // Remove all risk classes
      permissionItem.classList.remove(
        "none-risk",
        "low-risk",
        "medium-risk",
        "high-risk",
        "critical-risk"
      );
      // Add new risk class
      permissionItem.classList.add(`${this.value}-risk`);
      // Update select styling
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
    // Show save/cancel buttons
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
      // Hide save/cancel buttons
      editControls.classList.add("hidden");
      editAllBtn.classList.remove("hidden");

      // Reset all selects to original values and disable
      document.querySelectorAll(".risk-select").forEach((select) => {
        const originalRiskScore = select.getAttribute("data-original");
        select.value = originalRiskScore;
        select.disabled = true;
      });

      // Reset all textareas and hide
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
  // Clear existing report content first
  const reportSummary = document.getElementById("report-summary");
  const reportPermissions = document.getElementById("report-permissions");
  const reportRecommendations = document.getElementById(
    "report-recommendations"
  );

  reportSummary.innerHTML = "";
  reportPermissions.innerHTML = "";
  reportRecommendations.innerHTML = "";

  // Add summary to the report
  const summaryDiv = document.querySelector(".summary-text");
  const summaryText = Array.from(summaryDiv.children)
    .map((p) => p.textContent.trim())
    .join("<br><br>");
  const riskScore = document.getElementById("risk-score").innerHTML;

  reportSummary.innerHTML = `
    <div class="scrollable-content">
      Risk Score: ${riskScore}<br><br>
      ${summaryText}
    </div>
  `;

  // Add permissions to the report
  const permissions = document.querySelectorAll(".permission-item");
  let permissionsText = `The extension requires ${permissions.length} permissions:<br><br>`;

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

  reportPermissions.innerHTML = `<div class="scrollable-content">${permissionsText}</div>`;

  // Add recommendations to the report
  const recommendations = document.querySelectorAll(".recommendation-item");
  let recommendationsText = "";

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

  reportRecommendations.innerHTML = `<div class="scrollable-content">${recommendationsText}</div>`;
}
