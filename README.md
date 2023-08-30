# ACEMA O-RAN <img src="img/logo_transparent.png" height="180" align="right">

![Jupyter](https://img.shields.io/badge/Jupyter-F37626?logo=jupyter&logoColor=fff&style=for-the-badge)

This repository encompasses the set of code and data requisite for the replication of outcomes delineated in our paper "Towards Securing the 6G Transition: A Comprehensive Empirical Method to Analyze Threats in O-RAN Environments". The "Quickstart" section expounds upon the framework and essential prerequisites essential for executing the jupyter notebooks. ACEMA stands for _A Comprehensive Empirical Method to Analyze_.

## Short Overview

> In our paper, we present a new methodology that enables the MITRE ATT&CK framework to objectively assess specific threats in 6G Radio Access Networks (RANs). This helps address new security challenges that arise in the transition to open RANs.
> We analyze the O-Cloud component within the O-\gls{ran} ecosystem as a representative example, wherein no individual threat class demonstrates complete security.
> The inherent modularity of our approach ensures great adaptability and allows it to be applied to various other components within this system. This allows us to effectively detect and combat threats, thereby ensuring the resilience and security of future communication networks.

A detailed description as well as the findings of the investigation can be found in the [paper]().

## Requirements

Two code sections in both notebooks check whether all the required packages are installed. If this is not the case, they are automatically installed using `pip`. The necessary outsourced functions are also imported.

## Quickstart

There are only two main notebooks that are relevant. One for data collection and one for analysis. Within each notebook there is detailed documentation on the individual functions.

To reproduce the data, follow the steps below:

1. Execute all code blocks within the `O-Cloud - Data Gathering.ipynb`. This will create a folder called data, which is important for further analysis of the MITRE ATT&CK data.
2. You can then run all analyses within the notebook `O-Cloud - Data Analysis.ipynb`.

## Folder Structure

In total there are 4 associated folders:

- `data` _(This folder will be created after you initiate the download of the CTI data from GitHub)_
- `img` _(All plots that are created are saved here)_
- `mapping` _(In the mapping folder, the manually created mappings of threats are stored in CSV documents)_
- `scans` _(Contains the scan for the CAPEC'S -> CWE'S -> CVE'S for given CAPEC-ID'S)_

## Examples

![Publication figures](img/figures.png)

The code to generate the Figures included in the publication is in the `O-Cloud - Data Analysis.ipynb` notebook.

## Citation

The paper will be published in the special issue "Open RAN: A New Paradigm for Open, Virtualized, Programmable, and Intelligent Cellular Networks" of the IEEE Journal on Selected Areas in Communication in the fourth quater of 2023. As soon as a full bibtex citation is available, it will be included here.

If you use the provided code, please cite it as:

```bibtex
@article{klement2023acema,
  title = {Towards Securing the 6G Transition: A Comprehensive Empirical Method to Analyze Threats in O-RAN Environments},
  author = {Felix Klement, Wuhao Liu, Stefan Katzenbeisser},
  year = {2023},
  journal = {2023 IEEE JSAC special issue on Open RAN},
  keywords = {Security, Open RAN, Telecommunication, MITRE ATT\&CK, CVE, CWE}
}
```

## Release notes

See the [changelog](CHANGELOG.md) for changes between versions.

![Project logos](img/footer-logos.png)
