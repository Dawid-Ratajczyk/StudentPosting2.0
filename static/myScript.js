document.addEventListener("DOMContentLoaded", () => {
  const zoomablePosts = document.querySelectorAll(".zoomable-post");
  if (zoomablePosts.length) {
    const backdrop = document.createElement("div");
    backdrop.className = "post-modal-backdrop";
    document.body.appendChild(backdrop);

    const closeExpanded = () => {
      const opened = document.querySelector(".zoomable-post.expanded-center");
      if (opened) {
        opened.classList.remove("expanded-center");
      }
      backdrop.classList.remove("active");
      document.body.classList.remove("no-scroll");
    };

    const openExpanded = (post) => {
      const opened = document.querySelector(".zoomable-post.expanded-center");
      if (opened && opened !== post) {
        opened.classList.remove("expanded-center");
      }
      post.classList.add("expanded-center");
      backdrop.classList.add("active");
      document.body.classList.add("no-scroll");
    };

    zoomablePosts.forEach((post) => {
      const toggle = () => {
        if (post.classList.contains("expanded-center")) {
          closeExpanded();
        } else {
          openExpanded(post);
        }
      };
      post.addEventListener("click", toggle);
      post.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          toggle();
        }
      });
    });

    backdrop.addEventListener("click", closeExpanded);
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        closeExpanded();
      }
    });
  }

  const postImages = document.querySelectorAll(".post_img");
  postImages.forEach((img) => {
    const markReady = () => {
      img.classList.add("loaded");
      if (img.parentElement) {
        img.parentElement.classList.add("ready");
      }
    };
    if (img.complete) {
      markReady();
    } else {
      img.addEventListener("load", markReady, { once: true });
      img.addEventListener(
        "error",
        () => {
          if (img.parentElement) {
            img.parentElement.classList.add("ready");
          }
        },
        { once: true }
      );
    }
  });
});
