# Unified Patient Portal Reloaded - HMS

## 1. Vision & Architecture Separation
The **HMS Patient Portal** is a completely decoupled ecosystem from the **HMS ERP (Employee System)**. While the ERP is designed for high-density administrative tasks, the Patient Portal is a **User-Centric Care Hub**.

### 1.1 The "Core Compression" Strategy
Unlike employees who see CT1, CT2, and CT3 as separate workflows, patients will experience a **Unified Care Dashboard**. We are compressing the three Core Transaction subsystems into one seamless interface:
*   **CT1 (Access)**: Integrated as "My Appointments" & "Ward Stay".
*   **CT2 (Clinical)**: Integrated as "My Health Data" (Labs, Pharmacy, Nutrition).
*   **CT3 (Admin)**: Integrated as "Financials & Records".

---

## 2. Separate Landing Page: "HMS CareLink"
A public-facing endpoint (e.g., `/carelink`) designed with a premium, consumer-grade aesthetic.

### 2.1 Hero Experience
*   **Visuals**: High-fidelity imagery of personalized care and modern technology.
*   **Unified Entry**: A single, prominent "Patient Login" button that is visually distinct from the ERP "Admin Gateway".
*   **Value Props**:
    *   *Real-time Care Tracking*: View your labs as they are resulted.
    *   *Direct Specialist Access*: Skip the lines with digital booking.
    *   *Total Financial Clarity*: Itemized billing in your pocket.

---

## 3. The Unified Patient Dashboard: "The Care Hub"
Once logged in, the patient enters a single-page application (SPA) style dashboard.

### 3.1 Module: My Clinical Journey (Health & Data)
*   **Health Timeline**: A vertical feed showing past visits, current diagnosis, and upcoming tests.
*   **Results Center**: A "Glass-styled" card for Lab/Radiology reports with "Easy-Read" summaries (translating medical jargon to patient-friendly terms).
*   **Medication Manager**: Digital cabinet showing current prescriptions, dosage timers, and "Refill" buttons.

### 3.2 Module: My Hospital Stay (Facilities & Utilities)
*   **Room/Bed Info**: Live status of their ward stay, including the name of the attending nurse.
*   **Nutritional Concierge**: A digital menu showing their prescribed diet (from DNMS) with the ability to "Confirm Meal Arrival".
*   **Comfort Controls**: (Optional placeholder) for managing room utilities/feedback.

### 3.3 Module: My Financials (Billing & Insurance)
*   **The Live Bill**: A real-time running total of hospital costs, updated as services are rendered.
*   **Insurance Verification**: Digital wallet for health insurance cards and pre-authorization status.
*   **Payment Gateway**: One-click settlement via modern payment methods.

---

## 4. Technical Decoupling (The "No Mistakes" Check)
*   **Independent Auth Flow**:
    *   ERP Login: `/login` (Blue-Indigo theme).
    *   Patient Login: `/patient/auth` (Emerald-Teal theme).
*   **Route Prefixing**: All patient routes will be under `/carehub/*` to prevent collision with employee `/ct/*` routes.
*   **Unified API Layer**: A dedicated backend controller that aggregates data from all 3 CT databases into a single JSON response for the Patient Portal.

---

## 5. UI/UX Aesthetics
*   **Theme**: "Bio-Organic Glassmorphism". Soft rounded corners (3xl), translucent emerald gradients, and high-readability typography (Inter/Outfit).
*   **Micro-interactions**: Pulse-gradients on "Ready" laboratory results and smooth-slide transitions between care modules.
